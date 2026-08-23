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
 * nothing about what happens to their money. The way funds are actually lost
 * is specific and worth a sentence of its own: a Hub can put an old receipt on
 * chain while the owner is offline, the challenge window closes with nobody
 * answering for them, and the older, worse split settles. The Agent Wallet's
 * own acknowledgement has named this for a while. Fast Pay never did, and Fast
 * Pay is the path a phone takes by default.
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
  "I understand that the Hub holds my channel funds. If it stops answering, or if it puts an old receipt on chain while I am offline, I could lose part or all of what is in this channel. I will not put in more than I can afford to lose.";
