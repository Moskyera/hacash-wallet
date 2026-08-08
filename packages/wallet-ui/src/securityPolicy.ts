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
