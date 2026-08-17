/**
 * What the phone says about getting money out of a provider channel when the
 * provider has stopped answering.
 *
 * The phone is the device that is actually near the person on the day this
 * matters, and until now it said nothing about it at all. It cannot start an
 * exit and it never will: this handset holds a secure identity for approving,
 * not a Hacash key, so there is nothing here that could sign a channel
 * transaction. That is the whole reason this file is copy and not a control.
 *
 * Two rules it must not break:
 *  - It must not imply this phone can do it. An owner who believes the phone
 *    is the way out is an owner who does not go and find the desktop.
 *  - It must name the desktop control by its exact label. Two false
 *    instructions in this codebase caused a permanent, unrecoverable device
 *    revocation, and both were a sentence naming a control that did not exist.
 *    `registryExitRoute.test.ts` reads the desktop's own control table and
 *    fails if this string and that label ever drift apart.
 *
 * Copy only. No control flow, no gate, no validation, no call.
 */

/**
 * The exact label of the desktop control, character for character.
 *
 * Kept as a literal rather than imported because the phone bundle does not
 * include the desktop sources. The test imports both and compares them, which
 * is the check that actually matters.
 */
export const DESKTOP_EXIT_CONTROL_LABEL =
  "Take my money out without the provider";

/** The desktop page the control lives on, named the way that app names it. */
export const DESKTOP_EXIT_PAGE = "Security";

/**
 * The desktop section heading, which is what a person actually scans for.
 *
 * This is the part of the route that is true today. The control label above is
 * rendered on that page but is not yet pressable, so sending someone to hunt
 * for a button is sending them to a dead end - and this file's own header
 * records that two earlier false control-naming sentences caused a permanent,
 * unrecoverable revocation. Naming the section gets them to the right screen;
 * the screen itself then tells them the truth about the button.
 */
export const DESKTOP_EXIT_SECTION = "Getting your money out without the provider";

/** The desktop app, named the way the rest of this phone app names it. */
export const DESKTOP_APP_NAME = "AI Agent Wallet on HPAY Desktop";

export const REGISTRY_EXIT_TITLE = "If your provider stops answering";

/**
 * What is true about the money, said first.
 *
 * An owner reading this is frightened, and the single most useful fact is that
 * the provider cannot keep the money. It is deliberately not softened and not
 * overstated: the chain decides, there is a wait, and it costs fees.
 */
export const REGISTRY_EXIT_REASSURANCE =
  "Money in a provider channel is not held by your provider. It sits in a contract on the Hacash chain, and the chain, not the provider, decides who gets it. If your provider stops answering, you can still ask the chain to settle the channel and pay you.";

export const REGISTRY_EXIT_COST =
  "It is not instant and it is not free. The chain holds an objection window open first, so your provider has a fixed number of blocks to answer with a newer receipt, and only after that closes is your money sent. It costs three ordinary network fees, and those are spent whether or not your provider ever comes back.";

/**
 * The one thing that destroys the money rather than delaying it.
 *
 * It is on the phone because the clock is about a month long and the phone is
 * the device the owner has with them on day 30.
 */
export const REGISTRY_EXIT_LEASE =
  "A channel's record on the chain has an expiry date, roughly a month at a time, and it has to be extended before it runs out. When it expires the record does not vanish straight away: it goes dormant for several months more, and anyone at all can bring it back by paying its rent. Only if both of those run out is the deposit inside gone for good, for you and for your provider alike. Anyone at all can pay to extend it, so this is worth checking long before you need it.";

/** Why nothing on this screen is a button. */
export const REGISTRY_EXIT_PHONE_CANNOT =
  "This phone cannot start it. It holds an approval identity, not a Hacash key, so it can never sign a channel transaction by itself. Nothing on this screen spends anything or changes your channel.";

/** Where the control actually is, named exactly. */
export const REGISTRY_EXIT_ROUTE =
  `Open ${DESKTOP_APP_NAME} on the ${DESKTOP_EXIT_PAGE} page, where the section is called ${DESKTOP_EXIT_SECTION}. ` +
  "That screen shows how much is yours, how long the objection window is, and what it costs. " +
  `This build cannot yet send the exit for you: ${DESKTOP_EXIT_CONTROL_LABEL} is named there but is not pressable yet, and that screen says so in your own words rather than leaving you to find out. ` +
  "Your money is not lost and your receipts are still valid. What matters in the meantime is not letting the record above expire.";
