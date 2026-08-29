import { isOfficialNodeUrl } from "./nodeSettings";
import { mainnetSigningTransportIsEligible } from "./signingTransport";

/**
 * Can this node carry an ordinary on-chain payment?
 *
 * Mirrors `validate_l1_payment_node_url` in crates/wallet-core/src/settings.rs:
 * the strict signing rule, plus exactly one named exception for the official
 * endpoint on mainnet. `isOfficialNodeUrl` is what decides the exception, so a
 * lookalike host and a port variant of the official name are both refused.
 *
 * SEPARATE from `mainnetSigningTransportIsEligible` on purpose, and the two
 * must not be collapsed. Fast Pay channel opens and closes, dapp signing and
 * the L2 rail all still gate on the strict rule, and that rule does not move.
 * Only the plain L1 payment path gets the exception, and it pays for it with
 * the disclosure below.
 *
 * Deliberately module-private: `signingTransport.ts` is being given its own
 * copy of this predicate by concurrent work, and two exported names of the
 * same shape in one package is a collision. Whoever lands that work should
 * delete these two and import theirs.
 */
function l1PaymentTransportIsEligible(
  nodeUrl: string | null | undefined,
  networkMode: string | null | undefined,
): boolean {
  if (mainnetSigningTransportIsEligible(nodeUrl, networkMode)) return true;
  return l1PaymentUsesOfficialPlaintext(nodeUrl, networkMode);
}

/**
 * True when that named exception, and nothing else, is what permits the send.
 *
 * False for loopback, false for HTTPS and false off mainnet, so the disclosure
 * appears only where the cost is actually being paid.
 */
function l1PaymentUsesOfficialPlaintext(
  nodeUrl: string | null | undefined,
  networkMode: string | null | undefined,
): boolean {
  if (networkMode !== "mainnet") return false;
  const raw = nodeUrl?.trim();
  if (!raw) return false;
  if (mainnetSigningTransportIsEligible(raw, networkMode)) return false;
  return isOfficialNodeUrl(raw);
}

/** Minimum length enforced for passphrases that create or re-encrypt a wallet. */
export const MIN_NEW_WALLET_PASSPHRASE_LENGTH = 15;

/** Legacy encrypted backups remain readable; new passphrases use the stricter policy above. */
export const MIN_LEGACY_WALLET_PASSPHRASE_LENGTH = 8;

/**
 * Public, plain-language explanation of what the wallet protects and what it does
 * not. Linked from Settings on both platforms so the custody limits are one tap
 * away instead of buried in a repository.
 */
export const HOW_IT_WORKS_URL =
  "https://github.com/Moskyera/hacash-wallet/blob/main/docs/HOW-IT-WORKS.md";

/**
 * The same explanation for the AI Agent Wallet, which has a different custody
 * model. Everything else under docs/agent-wallet is engineering material for the
 * testnet pilot, so the owner is pointed at this one page rather than the folder.
 */
export const AGENT_WALLET_HOW_IT_WORKS_URL =
  "https://github.com/Moskyera/hacash-wallet/blob/main/docs/agent-wallet/HOW-THE-AGENT-WALLET-WORKS.md";

/**
 * The words a person reads before they put mainnet money behind a Hub.
 *
 * They live here, in one place both apps import, because they were previously
 * written out twice: apps/mobile/src/screens/FastPayChannelScreen.tsx and
 * apps/desktop/src/screens/FastPayScreen.tsx each carried their own copy, and
 * two copies of a promise are two chances for one of them to stop being true.
 *
 * Two things were wrong with what they said, and both are fixed here.
 *
 * First, neither named the loss. They said "Fast Pay depends on the selected
 * Hub and is not a trustless L1 exit", which is accurate and tells a person
 * nothing about what happens to their money.
 *
 * The mechanism it then named was the wrong one, and that was corrected on
 * 2026-08-23. It said a Hub can put an old receipt on chain while the owner is
 * offline and let a challenge window close on them. That is borrowed from the
 * HVM registry rail. Mainnet Fast Pay rides the NATIVE ChannelPay rail, where
 * no such thing can happen: the only close the chain registers is action 3,
 * and `channel_close` in the node
 * (`hacash-fullnodedev/mint/src/action/channel.rs`) calls `ctx.check_sign` on
 * BOTH the left and the right address before it will do anything. There is no
 * challenge action, no unilateral close, and no window to sleep through. A Hub
 * acting alone cannot move this money at all.
 *
 * Which makes the real risk the opposite shape, and worse to be vague about:
 * the money comes out only if the Hub co-signs. A Hub that stops answering
 * does not take the funds, it strands them, and there is nothing the owner can
 * sign by themselves to get them back. That is the sentence a person needs
 * before they fund a mainnet channel, so that is the sentence they get.
 *
 * Second, the ceilings were offered as the limits. They are not. They are what
 * this build refuses to cross. A Hub declares its own caps, and the only Hub
 * ever measured against mainnet declared a hundredth of these: 0.01 HAC per
 * payment, 0.1 per channel, 1 aggregate. A person reading "10 HAC per channel"
 * and sizing a deposit against it was reading our compile-time constant rather
 * than their Hub's answer.
 */

/** What no Hub may exceed, said as a ceiling rather than as an allowance. */
export const FAST_PAY_MAINNET_CEILINGS =
  "Fast Pay depends on the selected Hub and is not a trustless L1 exit. No Hub may exceed 1 HAC per payment, 10 HAC per channel and 100 HAC total TVL. Those are the ceilings this build refuses to cross, not the limits you get. A Hub declares its own and they are often far lower. What your Hub declares is what applies to you.";

/**
 * The checkbox label. It is the sentence itself, not a reference to a sentence,
 * so a person ticking it has read the thing they are agreeing to.
 */
export const FAST_PAY_MAINNET_CONSENT =
  "I understand that this channel can only be closed if the Hub co-signs it. There is no way for me to get this money out on my own: the chain requires both signatures, and no unilateral exit exists on this rail. If the Hub stops answering, refuses to sign, or disappears, what is in this channel stays locked and nobody can release it for me. I will not put in more than I can afford to lose.";

/**
 * Why pressing Enable on mainnet will not open a channel, said before it is
 * pressed rather than as the refusal that comes back.
 *
 * The checkbox above is exactly true and always was. What it never did was
 * stop anyone: ticking it opened a funded channel with no way out of it, which
 * is the stranding the whole close-voucher effort was meant to prevent, on the
 * one rail an ordinary person actually meets. The voucher was only ever built
 * for the Agent Wallet, so wallet-core now refuses the open instead.
 *
 * This does NOT replace the blocker sentence beside the declared caps. That
 * one appears only when the preflight reaches a Hub that discloses the gap.
 * This one does not depend on reaching anything, because the fact does not.
 *
 * It names the Agent Wallet rail because a refusal with no destination reads
 * as a broken build, and it says what that rail is: a Hub that countersigns
 * once because it chose to. Do not shorten that into a guarantee, and never
 * write "trustless" near it.
 *
 * THIS STRING RENDERS ON BOTH PLATFORMS, desktop at FastPayScreen and phone at
 * FastPayChannelScreen, so every word has to be true on both. It briefly said
 * the voucher sits "behind its own consent and its own build flag", and that
 * was wrong in the direction that costs a person a day. On the desktop the
 * build flag is already ON: the release workflow builds with
 * agent-wallet-bounded-mainnet-pilot and the shipped binary carries the
 * commands, so naming the flag makes the one gate the reader has already
 * passed sound like the expensive one, and points them away from the four that
 * actually stop them. On the phone it is worse than misleading: there is no
 * agent-wallet-core in the mobile graph at all and no voucher command in the
 * mobile ACL, so the sentence invited a person to go looking on their device
 * for something that is not on it.
 *
 * So it now names what really stands in the way, which is the same on both
 * platforms: a separate wallet holding separate money, and a person running
 * both the node and the Hub themselves. Do not reintroduce a phone-only or
 * desktop-only clause here. One of the two screens would be lied to.
 *
 * Kept deliberately shorter than the wallet-core refusal it previews. The
 * always-visible band on this screen is measured, and every word added to it
 * pushes something else towards the fold. The full sentence, with the reasons,
 * arrives from core the moment Enable is pressed.
 *
 * WHY THIS DID NOT GROW WHEN THE AGENT RAIL'S MAINNET GATE WAS SCOPED. The
 * core refusal now says something this preview deliberately does not: on the
 * Agent rail a close voucher can be taken and broadcast by its owner on
 * mainnet, which is what protects a deposit when the Hub stops answering. That
 * detail lives in MAINNET_CHANNEL_OPEN_WITHOUT_EXIT_REFUSAL, which arrives the
 * instant Enable is pressed.
 *
 * An earlier draft of this note also said the Hub-countersigned close "is still
 * refused there". It is not, and the claim is recorded here only so it is not
 * written back: `require_channel_binding_guarantees` demands trustless finality
 * under `TrustlessOnly`, while the policy every consented mainnet Agent user
 * gets is `TrustedBoundedPilot`, which asks only for the bounded pilot profile
 * and its flag. Neither this string nor the core one may claim to know whether
 * a co-signed close succeeds, because neither has contacted a Hub.
 *
 * They are not here because this string makes no claim they contradict. It says
 * a voucher exists only for the separate Agent Wallet and only for someone
 * running their own node and Hub, which was true before the scoping and is true
 * after it. Adding the distinction would cost roughly forty words in the one
 * band that is measured, to qualify a destination the reader has not chosen
 * yet. If a future change makes this preview claim that rail HAS a working
 * exit, the qualification stops being optional and something else on this
 * screen has to go to pay for it.
 *
 * That budget is not theoretical and there is almost no headroom in it. The
 * honest but wordier draft of this sentence, naming the Hacash full node and
 * the Fast Pay Hub in full and adding "it is not something you can switch on
 * here", pushed the always-visible share of the Fast Pay screen from 0.4485 to
 * 0.4592 against a ceiling of 0.45 and failed the volume test the owner's
 * complaint about clutter is pinned by. The right response was to say the same
 * thing in fewer words, not to raise the ceiling. If you need to add a clause
 * here, take one out.
 */
export const FAST_PAY_MAINNET_CHANNEL_REFUSED =
  "This wallet will not open a mainnet Fast Pay channel, because it has no way out of one: every close it can build has to be countersigned by the Hub, and it cannot take a close voucher. A close voucher exists only for the separate Agent Wallet, and only if you run your own node and Hub. An already open channel still closes through the Hub, and testnet is untouched.";

/**
 * The operator instructions, linked rather than named.
 *
 * Both hub panels used to print the bare repository path
 * `docs/HUB-OPERATOR.md` as inline code. In a desktop or phone app that is not
 * a route to anything: there is no repository on the machine to open it from.
 * The link mechanism already existed for HOW_IT_WORKS_URL, so the reference
 * becomes one.
 */
export const HUB_OPERATOR_URL =
  "https://github.com/Moskyera/hacash-wallet/blob/main/docs/HUB-OPERATOR.md";

/**
 * What the Fast Pay empty state says when there is no provider.
 *
 * The wallet's entire provider directory is one loopback address. On a fresh
 * mainnet install nothing answers it, so a person was shown "Not set up yet"
 * and a "Discover hubs" button that reported "No online hubs found", with no
 * indication that the reason is that no such thing exists yet rather than that
 * they had done something wrong.
 *
 * Shipping an invented preset would be worse than shipping none. So the empty
 * state says the true thing instead: there is no public Hub, using this rail
 * on mainnet means somebody runs one, and that somebody can be you.
 */
export const FAST_PAY_NO_HUB_EXPLANATION =
  "There is no public Fast Pay provider and no directory to search. Nobody has published one. Using Fast Pay on mainnet means someone runs a Hub and a synchronized HPAY-compatible full node, and points this wallet at it. If a provider gave you an address, paste it below.";

/**
 * The sentence a person needs before they decide to be their own provider.
 *
 * Running your own Hub is the only way to reach this rail today, and it is
 * genuinely the safest available configuration. It does not remove the risk
 * the consent text describes; it changes who bears it. Saying "run your own
 * Hub" without saying this reads as a workaround for the stranding warning
 * rather than a different arrangement of the same exposure.
 */
export const FAST_PAY_SELF_HOSTED_HUB_NOTE =
  "If you run the Hub yourself, you are the counterparty to your own channel. That does not remove the risk above. It means the co-signature your money depends on is yours, so losing that Hub's key or its durable state strands your own funds with nobody to ask.";

/**
 * Is the Hub this wallet is pointed at almost certainly the owner's own machine?
 *
 * It decides ONE thing: whether FAST_PAY_SELF_HOSTED_HUB_NOTE is read without
 * opening anything, or folded in with the rest of the hub material. It gates
 * nothing and it is never used to permit anything.
 *
 * It fails towards SHOWING the note. The consent text says "if the Hub stops
 * answering, refuses to sign, or disappears", and an owner running the Hub on
 * their own machine reads that as somebody else's failure when it is their own
 * key and their own durable state. Getting that wrong in the quiet direction
 * leaves a person believing something untrue, so an empty URL, an unparseable
 * one, a loopback address, a `.local` name and a private LAN address all count
 * as self-hosted. Only a real public host counts as somebody else's Hub.
 */
export function hubIsProbablySelfHosted(hubUrl: string | null | undefined): boolean {
  const raw = hubUrl?.trim();
  if (!raw) return true;
  let host: string;
  try {
    host = new URL(raw).hostname.toLowerCase();
  } catch {
    return true;
  }
  if (host === "" || host === "localhost" || host.endsWith(".localhost")) return true;
  if (host === "::1" || host === "[::1]") return true;
  if (host.endsWith(".local")) return true;
  if (/^127\./.test(host)) return true;
  if (/^10\./.test(host)) return true;
  if (/^192\.168\./.test(host)) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[01])\./.test(host)) return true;
  return false;
}

/**
 * What a bounded-pilot Hub will not tell you until it refuses.
 *
 * The Hub publishes `allowlist_configured: true` and deliberately never
 * publishes who is on the list, which is correct: an unauthenticated endpoint
 * listing every pilot participant's address would be a leak. The consequence
 * is that a person cannot learn whether they are admitted until after they
 * have prepared, authenticated and submitted a channel open. Naming the
 * requirement up front removes most of that surprise without publishing
 * anything.
 */
export const FAST_PAY_PILOT_ALLOWLIST_NOTE =
  "Bounded pilot Hubs admit named addresses only. The operator has to add your address before setup will work, and a Hub will not say who is on its list. Send them the address shown on your Home screen first.";

/**
 * The one line a person reads instead of the five paragraphs about hubs.
 *
 * A summary is only allowed to replace a risk if it is as honest as the risk.
 * These two sentences carry the whole of what the folded text says that matters
 * before a decision: there is no public hub, somebody has to run one, and
 * running your own moves the exposure rather than removing it. Nothing in here
 * is softer than what it summarises, and every word of the long form is still
 * in the document behind it.
 */
export function hubSourcesSummary(isMainnet: boolean): string {
  const base =
    "Where hubs come from. There is no public hub and no directory; somebody has to run one and it can be you.";
  if (!isMainnet) return base;
  return `${base} Pilot hubs admit named addresses only, and running your own moves this risk to you rather than removing it.`;
}

/**
 * Why a plain mainnet install cannot sign, said before the ceremony.
 *
 * The rule is correct and stays: signing against a plaintext remote endpoint
 * lets anyone on the path choose the transaction bytes and the reported chain
 * state. What was wrong is that no screen mentioned it, and the refusal
 * arrived from deep inside execution, after the review screen and after the
 * fingerprint prompt. This is the same rule stated as a visible condition.
 */
export const MAINNET_SIGNING_TRANSPORT_NOTICE =
  "Fast Pay cannot be set up or closed through this node on mainnet. That needs HTTPS, or a node running on this same machine, and the official node is plain HTTP and remote. Ordinary on-chain payments do go through the official node, as a stated exception with a stated cost; a channel open or close does not, because it puts money behind a countdown that only a node you trust should be timing. Point the wallet at your own node, usually http://127.0.0.1:8080, in Settings.";

/**
 * The one address `candidate_urls` looks at on this machine.
 *
 * Mirrors `LOCAL_NODE_URL` in crates/wallet-core/src/node_discovery.rs. It is
 * named here because the sentence below promises that "Find active node" will
 * pick the node up, and that promise is only true at this address. Telling
 * somebody to start a node and then silently not finding it is the same dead
 * end one step further along.
 */
export const LOCAL_NODE_ADDRESS = "http://127.0.0.1:8080";

/**
 * What this payment costs, or null when it costs nothing.
 *
 * The core permits an ordinary L1 payment through the official endpoint as one
 * named exception, so a screen must not call that node blocked. Permitted is
 * not the same as free, though, and the difference is the whole point of this
 * function: the disclosure is what the exception is paid for with.
 *
 * Both the predicate and the words come from `signingTransport.ts`, which
 * mirrors the core. Nothing is restated here, because a second copy of a
 * disclosure is a second chance for one of them to stop being true.
 */
export function officialNodePlaintextDisclosure(
  nodeUrl: string | null | undefined,
  networkMode: string | null | undefined,
): string | null {
  if (!l1PaymentUsesOfficialPlaintext(nodeUrl, networkMode)) return null;
  return (
    `This wallet is talking to the official Hacash node over plain HTTP, because that node offers ` +
    `nothing else. Whoever carries your traffic (your wifi, your ISP, a VPN) can read which address ` +
    `you are asking about and see the payment go out, so it links your address to your connection. ` +
    `They can also quote a wrong network fee, which is why the fee below is worth reading. They ` +
    `cannot change who gets paid or how much, they cannot sign anything for you, and they cannot ` +
    `swap in a different chain. Running Hacash on your own computer and pointing this wallet at ` +
    `${LOCAL_NODE_ADDRESS} removes all of it.`
  );
}

/**
 * The refusal, for a node that genuinely cannot carry a payment.
 *
 * `MAINNET_SIGNING_TRANSPORT_NOTICE` renders in exactly one place in the whole
 * product, on the Fast Pay screen, which is a feature a plain sender never
 * turns on. So the person who installed a wallet to send HAC to a friend met
 * this rule for the first time as a raw core string in a toast, after typing
 * an address and an amount: "mainnet signing requires HTTPS, except for a node
 * on this same device". No next step, and the Settings screen was at that
 * moment telling them the node they were on was the official one and advising
 * them not to change it.
 *
 * This now keys off the L1 payment rule rather than the strict signing rule,
 * because keying it off the strict rule blocked the shipped default, which the
 * core permits. A disabled button in front of a send the core would have
 * accepted is a worse dead end than the toast it replaced.
 *
 * Returns null when the wallet CAN carry the payment, so a screen can render
 * this unconditionally and it simply disappears once the condition is met.
 */
export function plainSendBlockedNotice(
  nodeUrl: string | null | undefined,
  networkMode: string | null | undefined,
): string | null {
  if (l1PaymentTransportIsEligible(nodeUrl, networkMode)) return null;
  const node = nodeUrl?.trim() ? nodeUrl.trim() : "the node this wallet is set to";
  return (
    `You can see your balance, but this wallet cannot send yet. Sending means signing a payment, ` +
    `and it will only sign through a Hacash node running on this same computer, or one reached over HTTPS. ` +
    `It is currently reading from ${node}, which is plain HTTP on somebody else's server, so anyone ` +
    `between you and it could change what you sign. Start a Hacash node on this computer with its ` +
    `HTTP API on ${LOCAL_NODE_ADDRESS}, then use "Find active node" in Settings and this wallet will ` +
    `pick it up. If you already run one on a different port, type that address into the node field ` +
    `in Settings instead.`
  );
}

/**
 * The reason, short enough to sit on the button it disables.
 *
 * A disabled control with no label is its own dead end. The person pressed
 * Send, nothing happened, and there was nothing to read.
 */
export function plainSendBlockedButtonLabel(
  nodeUrl: string | null | undefined,
  networkMode: string | null | undefined,
): string | null {
  if (l1PaymentTransportIsEligible(nodeUrl, networkMode)) return null;
  return "Cannot send: no Hacash node on this computer";
}

/**
 * The requirement that stops every Agent Wallet payment, said before funding
 * rather than at the first approval.
 *
 * `approve` refuses with `WitnessPhoneRequiredForApproval` unless a witness
 * capable phone is paired, and that gate is compiled into shipped builds. The
 * gate is right and stays: a completed approval signs into
 * `SignedAwaitingWitness`, which only a phone holding the rollback anchor can
 * advance. No sweep expires it, it holds its reservation, and it blocks every
 * later payment from getting an anchor, so approving without a witness phone
 * strands the payment in a state with no exit.
 *
 * What was wrong is only when a person learned about it: after creating the
 * wallet and after funding it, at the moment of their first payment. Saying it
 * at creation costs nothing and removes the whole surprise.
 */
export const AGENT_WITNESS_PHONE_REQUIREMENT =
  "Before this wallet can approve any payment, you have to pair a phone as its witness. Approving signs the transaction and then waits for that phone to confirm it, so an Agent Wallet with no witness phone can hold funds and spend nothing. Pair one from the Security page after you create the wallet, and before you fund it.";
