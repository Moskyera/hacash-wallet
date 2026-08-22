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
 */
export function privacyNotice(
  security: MessengerPeerSecurity | null | undefined,
): PrivacyNotice | null {
  if (!security) return null;
  const unsealed = security.unsealed_messages ?? 0;
  if (!security.sends_sealed) {
    return {
      text: "Not sealed to this contact yet. Nothing they have sent has reached this wallet, so it holds no key of theirs and the relay operator can read what you send here. That changes once they write to you.",
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
