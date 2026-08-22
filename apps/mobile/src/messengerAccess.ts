import type { WalletStatus } from "./api";

/**
 * Why the messenger cannot be opened on this wallet, or null when it can.
 *
 * The Messages entry was offered to every wallet, including the two that can
 * never open a message store: a watch-only identity and a Cold Vault, neither
 * of which has the signing key the store is sealed with. Opening it threw the
 * raw policy string from crates/wallet-core/src/wallet.rs at the person, once
 * on open and again every fifteen seconds after that. One of those strings told
 * them to use "a freshly authorized prepared Type 2 air-gap operation", which
 * is not something that exists for messages: an instruction pointing at a
 * control nobody can find.
 *
 * These sentences say what is true and stop there. None of them names an action
 * the wallet does not offer. The refusal itself still lives in the core; this
 * only decides whether the screen asks at all.
 */
export function messengerBlockedReason(status: WalletStatus | null | undefined): string | null {
  if (!status || status.locked) return "Unlock the wallet to open your messages.";
  if (status.watch_only) {
    return "This is a watch-only wallet, so the signing key is not on this phone. Your message history is sealed with that key and cannot be opened here.";
  }
  if (status.hardware_signing_mode === "airgap_only") {
    return "Cold Vault keeps the signing key off this phone. Your message history is sealed with that key and cannot be opened here.";
  }
  return null;
}
