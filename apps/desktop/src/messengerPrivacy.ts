import type { MessengerPeerSecurity } from "./api";

export type PrivacyNotice = { text: string; tone: "ok" | "warn" };

/**
 * The only sentence the screen is allowed to say about a conversation.
 *
 * Three things were wrong with the sentence this replaces.
 *
 * It said "end-to-end encrypted" about the whole conversation on the strength
 * of a flag that only describes the NEXT message: a thread can be sealed from
 * here on while every message above the banner travelled under v1, whose key is
 * derived from the two addresses the relay stores in clear. So the count of
 * messages not known to be sealed is stated too, and it is a count of
 * `sealed !== true`, which covers both "known v1" and "written before the
 * wallet recorded this", the only claim the stored data supports.
 *
 * It said "the relay carries the ciphertext only", which is false: the
 * envelope carries the two addresses, the sender's public key and the time in
 * clear beside the body (crates/dust-whisper/src/protocol.rs).
 *
 * And it sat above messages whose sender nobody had checked. That part is
 * fixed in the wallet rather than in words: an envelope is refused unless it
 * is signed by the key its sender address derives from.
 *
 * `null` in means the wallet was not asked or did not answer, and the screen
 * then says nothing rather than guessing.
 *
 * `sends_sealed: false` is a fact about what this wallet holds on disk, not a
 * prediction. The first message of a conversation can now be sealed to a key
 * fetched from a relay and checked against the recipient's own address
 * (`lookup_peer_key`, crates/wallet-core/src/messenger.rs), so the banner in
 * that state says what will be tried and what happens if it fails, and points
 * at the per-message marker for what actually happened. It promises neither.
 *
 * It also names the cost of asking, because that cost is paid by the person
 * reading the banner and not by them alone. The lookup walks every relay this
 * wallet is configured with until one answers with a key that survives the
 * check, while the send itself stops at the first relay that accepts the
 * envelope. So a relay that never carries this message can still be told the
 * recipient's address. Section 6.1 of docs/RUNNING-A-RELAY.md says the same
 * thing from the operator's side.
 */
export function privacyNotice(
  security: MessengerPeerSecurity | null | undefined,
): PrivacyNotice | null {
  if (!security) return null;
  const unsealed = security.unsealed_messages ?? 0;
  if (!security.sends_sealed) {
    return {
      text: "Not sealed to this contact yet. Nothing they have sent has reached this wallet, so it holds no key of theirs. Before sending, this wallet asks the relays you have named whether they have seen a key for this address, and uses an answer only if that key proves it belongs to this address. Asking tells a relay who you are about to write to, including a relay that never carries the message. If no key survives the check, the relay operator can read what you send here. Either way the message is marked with which way it actually travelled.",
      tone: "warn",
    };
  }
  if (unsealed > 0) {
    return {
      text: `New messages you send here are sealed to this contact's own key. ${unsealed} message(s) already in this conversation are not known to have been, so treat those as readable by the relay. The relay always sees both addresses and the time.`,
      tone: "warn",
    };
  }
  return {
    text: "New messages you send here are sealed to this contact's own key, and every message in this conversation was. The relay still sees both addresses and the time.",
    tone: "ok",
  };
}

/** Per-message marker, or null when there is nothing verified to say. */
export function sealedLabel(sealed: boolean | null | undefined): string | null {
  if (sealed === true) return "Sealed to their key";
  if (sealed === false) return "Not sealed";
  return null;
}
