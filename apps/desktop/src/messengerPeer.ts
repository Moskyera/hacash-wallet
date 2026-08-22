import type { ParsedAddress } from "@hacash/wallet-ui";

/**
 * Who a message may be addressed to.
 *
 * The wallet already owns the only real address decoder, in Rust
 * (`hacash_wallet_core::parse_address`, reached from here through
 * `api.inspectAddress`). Nothing in this file re-implements base58check: a
 * string that is not an address fails inside that call and the caller shows
 * the decoder's own message.
 *
 * What is left is the question the decoder does not answer - whether the
 * address can ever *collect* a message. Fetching an inbox means signing the
 * relay's challenge with the secp256k1 key that derives to the claimed
 * address, and that derivation always produces a version 0 account address
 * (`Account::get_address_by_public_key`). A contract, P2SH, PQC or hybrid
 * address therefore has no key anywhere that could claim its inbox, so a
 * message sent to one is undeliverable no matter how healthy the relay is.
 *
 * `crates/wallet-core/src/messenger.rs::require_messenger_peer` enforces the
 * same rule on the send itself. This is the earlier, kinder copy: it stops a
 * typo at the point it was typed, before a message is composed against it.
 */
export const PEER_HAS_NO_INBOX_TEXT =
  "Messages can only be sent to a standard Hacash account address, the kind that starts with 1. " +
  "This address has no signing key behind it, so it could never collect a message.";

/** `null` when this address may be opened as a conversation. */
export function peerRefusal(parsed: ParsedAddress): string | null {
  return parsed.kind === "private_key" ? null : PEER_HAS_NO_INBOX_TEXT;
}
