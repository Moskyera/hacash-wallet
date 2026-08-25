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
  "This node can show balances but cannot be used to sign on mainnet. Signing needs HTTPS, or a node running on this same machine. The official node is plain HTTP and remote, so it is readable and not signable. Point the wallet at your own node, usually http://127.0.0.1:8080, in Settings.";

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
