import { invoke } from "@tauri-apps/api/core";
import type {
  AirgapInspection,
  AssetPriceResponse,
  CanonicalTransaction,
  HacdDiamondInfo as SharedHacdDiamondInfo,
  NodeCapabilities,
  ParsedAddress,
  Type4ProbeResult,
} from "@hacash/wallet-ui";
export type { HacdDiamondBornInfo, HacdDiamondInfo } from "@hacash/wallet-ui";

export type PrivacySettings = {
  hide_balances: boolean;
  hide_addresses: boolean;
  screen_privacy: boolean;
  store_tx_history: boolean;
  clipboard_clear_secs: number;
  pause_auto_lock_dapp: boolean;
};

export type HubFeePayer = "sender" | "recipient";

export type L1FeeSpeed = "slow" | "normal" | "fast" | "ultra";

export type SendPreferences = {
  hub_fee_payer: HubFeePayer;
  prefer_fast_pay: boolean;
  l1_fee_speed?: L1FeeSpeed;
  service_fee_enabled?: boolean;
  service_fee_rate?: number;
};

export type SendOptions = {
  hub_fee_payer: HubFeePayer;
  force_l1: boolean;
  l1_fee_speed?: L1FeeSpeed;
  service_fee_enabled?: boolean;
  service_fee_rate?: number;
};

export type L1FeeTierQuote = {
  speed: L1FeeSpeed;
  label: string;
  detail: string;
  fee_mei: number;
  fee_wire: string;
};

export type SendFeeBreakdown = {
  payer_debit_mei: number;
  recipient_credit_mei: number;
  hub_fee_mei: number | null;
  hub_fee_payer: HubFeePayer;
  l1_fee_wire: string | null;
  l1_fee_mei: number | null;
  service_fee_mei?: number | null;
  service_fee_rate?: number | null;
  service_fee_treasury?: string | null;
};

export type DustWhisperSettings = {
  enabled: boolean;
  relay_urls: string[];
  fallback_direct: boolean;
  auto_start_relay: boolean;
};

export type RelayHealthStatus = {
  url: string;
  online: boolean;
  error: string | null;
  node_url: string | null;
  protocol_version: number | null;
};

export type SigningPolicy = "software" | "webauthn_gate" | "airgap_only" | "watch_only";

export type WalletSettings = {
  node_url: string;
  node_fallback_urls?: string[];
  auto_node_failover?: boolean;
  network_mode?: "mainnet" | "testnet";
  l2_hub_url: string | null;
  trusted_mainnet_fast_pay_pilot: boolean;
  hub_right_address: string | null;
  channel_id_hex: string | null;
  webauthn_enabled: boolean;
  biometric_send_enabled?: boolean;
  biometric_unlock_enabled?: boolean;
  security_profile: string;
  hardware_signing_mode?: SigningPolicy;
  require_second_factor_above_mei?: number | null;
  privacy: PrivacySettings;
  dust_whisper?: DustWhisperSettings;
  send?: SendPreferences;
};

export type BackupPreview = {
  address: string;
  format: "full_authenticated" | "legacy_classic_only";
  version: number;
  encrypted: boolean;
  addressVerified: boolean;
  requiresLegacyConfirmation: boolean;
  included: string[];
  warning: string | null;
};

export type WalletStatus = {
  has_wallet: boolean;
  locked: boolean;
  address: string | null;
  security_profile: string;
  node_url: string;
  network_mode: "mainnet" | "testnet";
  l2_enabled: boolean;
  fast_pay_state: string;
  fast_pay_message: string;
  /** Non-null when the key was derived from a guessable phrase. */
  legacy_key_derivation: string | null;
  watch_only: boolean;
  privacy: PrivacySettings;
  dust_whisper?: DustWhisperSettings;
  seconds_until_lock: number | null;
  channel_id: string | null;
  hardware_signing_mode: SigningPolicy;
  require_second_factor_above_mei: number;
  signing_available: boolean;
};

export type NodeCandidateStatus = {
  url: string;
  online: boolean;
  network_match: boolean;
  height: number | null;
  diamond: number | null;
  error: string | null;
};

export type NodeDiscoveryReport = {
  active_node: string;
  switched: boolean;
  network_mode: "mainnet" | "testnet";
  candidates: NodeCandidateStatus[];
  /**
   * Set when automatic failover found a working node and deliberately did not
   * move to it, because moving would have traded a node this wallet can sign
   * against for one it cannot. Absent from older cores.
   */
  failover_declined?: string | null;
};

export type MessageDirection = "in" | "out";

export type ChatMessage = {
  id: string;
  peer: string;
  direction: MessageDirection;
  body: string;
  timestamp_utc: string;
  delivered: boolean;
  /**
   * Whether this one message travelled sealed to the peer's own key (v2).
   * `false` is v1, whose key comes from the two addresses the relay holds in
   * clear. `null` or absent is a record written before the wallet tracked it,
   * about which nothing is known.
   */
  sealed?: boolean | null;
  /**
   * When this wallet took delivery of an incoming message, by its own clock.
   *
   * `timestamp_utc` is the sender's own signed claim, and a relay that holds a
   * message back for a week hands that claim over untouched. The conversation
   * is ordered on this instead. Absent on outgoing messages and on records
   * written before the wallet kept it.
   */
  received_utc?: string | null;
  /**
   * Why no relay took an outgoing message, in the relay's own words.
   *
   * "No relay accepted it" used to be the whole story, so a relay that was down
   * and a recipient whose mailbox was full read identically.
   */
  delivery_error?: string | null;
  /**
   * WHICH relay accepted an outgoing message, when one did.
   *
   * A send stops at the first relay in the list that accepts, and a wallet
   * hosting its own relay always has one that accepts: its own, on this
   * machine. So `delivered: true` was also the answer for a message that never
   * left the computer it was typed on, while the friend's replies kept
   * arriving because collecting mail tries every relay. Absent on incoming
   * messages, on undelivered ones, and on records written before this existed.
   */
  delivered_via?: string | null;
};

/** What the screen may say about one conversation's privacy. */
export type MessengerPeerSecurity = {
  /** The wallet holds a verified key for this peer, so the next send is sealed. */
  sends_sealed: boolean;
  /** Messages already in the thread that are not known to have been sealed. */
  unsealed_messages: number;
};

/**
 * What one pass over the configured relays actually managed to do.
 *
 * A bare count cannot separate an empty inbox from a relay that never answered
 * or one that refused the claim, and the screen used to report all three as
 * "nothing new".
 */
export type MessengerPollOutcome = {
  added: number;
  relays_tried: number;
  relays_answered: number;
  relays_refused: number;
  rejected_envelopes: number;
  /**
   * Correctly signed envelopes whose body this wallet could not open, cleared
   * from the relay rather than left there. Left there, they held the inbox at
   * the relay's cap and every correspondent was refused with "inbox full"
   * while the owner was told there was nothing new.
   */
  undecryptable: number;
  /** The local store is at its ceiling, so messages were left on the relay. */
  store_full: boolean;
};

export type ChatThread = {
  peer: string;
  /** The newest message in the thread, cut short for the list row. */
  last_message: string;
  /** The sender's own claim about when the newest message was written. */
  last_timestamp_utc: string;
  /** When this wallet last saw activity here. The list is ordered on this. */
  last_activity_utc: string;
  unread: number;
};

export type FastPayStatus = {
  state: string;
  message: string;
  can_enable: boolean;
  hub_url: string | null;
  provider_name: string | null;
  default_deposit_mei?: number;
};

export type FastPayInboxItem = {
  payment_id: string;
  idempotency_key: string;
  payer: string;
  payee: string;
  amount: string;
  channel_id: string;
  payee_channel_id: string;
  status: string;
  bill_hex: string;
  summary: string | null;
  created_at: number;
};

export type FastPayExecution = {
  payment_id: string;
  status: string;
  summary: string;
};

export type HubHealth = {
  ok: boolean;
  version: number;
  name?: string;
  hub_address?: string;
  hub_fee_mei?: string | number;
  settlement_ready?: boolean;
  cross_channel_ready?: boolean;
  trusted_bounded_pilot_ready?: boolean;
  deployment_profile?: string;
};

export type HubDiscoveryEntry = {
  id: string;
  name: string;
  hub_url: string;
  online: boolean;
  hub_address: string | null;
  hub_fee_mei: string | null;
  error: string | null;
};

export type HubDiscoveryReport = {
  hubs: HubDiscoveryEntry[];
  online_count: number;
};

export type Hip23Check = {
  ok: boolean;
  warnings: string[];
  errors: string[];
};

export type SendPreview = {
  plan: {
    rail: "L2Fast" | "L1OnChain";
    summary: string;
    estimated_fee: string;
    rail_label: string;
    rail_detail: string;
    fee_breakdown: SendFeeBreakdown;
    l1_fee_tiers?: L1FeeTierQuote[];
    // Set when the wallet had Fast Pay set up for this send and chose
    // not to use it. The blockchain fallback is correct; doing it in
    // silence was not.
    fast_pay_declined?: string | null;
    // Set when the fee above is a guess rather than a quote, because the node
    // did not answer the fee query or could not build the body. The fallback
    // is correct; showing an invented fee as though the network had quoted it
    // was not. An under-priced transfer that sits unconfirmed inside a channel
    // challenge window loses the window, and the older split settles.
    fee_estimate_degraded?: string | null;
  };
  from: string;
  to: string;
  amount_mei: number;
  hip23: Hip23Check;
};

export type PreparedOperationView = {
  id: string;
  digest: string;
  kind: "hac_l1" | "hacd" | "bridged_btc" | "channel_open" | "channel_close" | string;
  wallet_address: string;
  network_mode: string;
  chain_id: number | null;
  display: {
    title: string;
    summary: string;
    fields: Array<{ label: string; value: string }>;
  };
  authorization_required: boolean;
  webauthn_required: boolean;
  expires_in_secs: number;
};
export type SendResult = {
  rail: string;
  tx_hash: string;
  summary: string;
  pending: boolean;
};

export type TxStatus = "confirmed" | "pending" | "failed";

export type TxRecord = {
  tx_hash: string;
  rail: string;
  from: string;
  to: string;
  amount_mei: number;
  summary: string;
  timestamp: string;
  status?: TxStatus;
};

export type BillSummary = {
  payment_id: string;
  timestamp_utc: string;
  channel_legs: number;
  dispute_ready: boolean;
  hex_byte_length: number;
  signatures: { address: string; filled: boolean; verified: boolean }[];
};

export type PlatformSecurityStatus = {
  native_biometric_available: boolean;
  platform: string;
  biometric_kind?: string | null;
};

export type BiometricUnlockStatus = {
  enabled: boolean;
  configured: boolean;
  keySecurityLevel: string;
  hardwareBacked: boolean;
  strongBoxBacked: boolean;
  authenticationEnforcedBySecureHardware: boolean;
  authPerUse: boolean;
};

export type PassphraseChangeOutcome = {
  biometricUnlockDisabled: boolean;
  nativeBiometricSecretCleared: boolean;
  warning: string | null;
};

export type AssetSummary = import("@hacash/wallet-ui").AssetSummary;
export type NativeAssetSendPreview = import("@hacash/wallet-ui").NativeAssetSendPreview;
export type NativeAssetMetadata = import("@hacash/wallet-ui").NativeAssetMetadata;

export type ChannelPartyBalance = {
  address: string;
  hacash: string;
  satoshi: number;
};

export type ChannelInfo = {
  id: string;
  status: number;
  left: ChannelPartyBalance;
  right: ChannelPartyBalance;
};

export type ChannelSetupPreview = {
  channel_id: string;
  reuse_version: number;
  left_address: string;
  right_address: string;
  left_deposit: string;
  right_deposit: string;
};

export type BtcSendPreview = {
  from: string;
  to: string;
  satoshi: number;
  btc_amount: number;
  service_fee_satoshi: number;
  service_fee_btc: number;
  total_debit_satoshi: number;
  service_fee_treasury: string;
  fee_mei: number;
  fee_wire: string;
  hip23: Hip23Check;
  summary: string;
};

export type DeclaredHubCaps = {
  max_payment_hac: string | null;
  max_channel_funding_hac: string | null;
  max_aggregate_tvl_hac: string | null;
  aggregate_tvl_within_limit: boolean | null;
};

/**
 * One Hub answering for itself. Every field is transcribed from that Hub's
 * /v1/health and /v1/readiness/mainnet, so a person choosing a provider sees
 * the Hub's declared caps and the Hub's own named blockers rather than this
 * build's compile-time ceilings. Read-only: the readiness document is
 * re-fetched and re-gated at the signing boundary regardless.
 */
export type HubDeclaration = {
  hub_url: string;
  reachable: boolean;
  error: string | null;
  name: string | null;
  hub_address: string | null;
  version: number | null;
  settlement_ready: boolean;
  cross_channel_ready: boolean;
  hub_fee_mei: string | null;
  deployment_profile: string | null;
  mainnet_checked: boolean;
  readiness_profile: string | null;
  payments_enabled: boolean | null;
  declared_caps: DeclaredHubCaps;
  blockers: string[];
  disclosed_blockers: string[];
  limitations: string[];
  readiness_error: string | null;
};

export type AirgapUnsigned = {
  v: number;
  from: string;
  to: string;
  amount_mei: number;
  amount_wire: string;
  fee: string;
  service_fee_mei: number;
  service_fee_treasury: string | null;
  body_hex: string;
  summary: string;
  tx_type?: number;
};

export type AirgapSigned = {
  v: number;
  from: string;
  to: string;
  amount_mei: number;
  amount_wire: string;
  fee: string;
  service_fee_mei: number;
  service_fee_treasury: string | null;
  signed_hex: string;
  summary: string;
  tx_type?: number;
};

export type AirgapEnvelope =
  | (AirgapUnsigned & { kind: "unsigned" })
  | (AirgapSigned & { kind: "signed" });

export type AirgapPrepareResult = {
  envelope: AirgapUnsigned;
  inspection: AirgapInspection;
  qr_parts: string[];
};

export type AirgapSignResult = {
  envelope: AirgapSigned;
  inspection: AirgapInspection;
  qr_parts: string[];
};

export type AirgapParseResult = {
  envelope: AirgapEnvelope | null;
  inspection?: AirgapInspection | null;
  needs_more_parts: boolean;
  received_parts: number;
  total_parts: number;
};

export type HacdSendPreview = {
  from: string;
  to: string;
  diamond_name: string;
  diamond_names: string[];
  diamond_count: number;
  diamond_number?: number | null;
  fee_mei: number;
  fee_wire: string;
  service_fee_mei: number;
  service_fee_treasury: string;
  total_hac_debit_mei: number;
  hip23: Hip23Check;
  summary: string;
};

export type QuantumAccountInfo = {
  kind: string;
  address: string;
  address_version: number;
  alg_id: number;
  mldsa_pubkey: string;
  secp_pubkey: string;
};

export type QuantumAccountSummary = {
  kind: string;
  address: string;
  address_version: number;
};

export type QuantumSettings = {
  quantum_mode: boolean;
  active_account: QuantumAccountSummary | null;
};

export type QuantumPreflight = {
  ok: boolean;
  warnings: string[];
  errors: string[];
  balance_mei: number;
  fee_wire: string;
  fee_mei: number;
  service_fee_mei: number;
  service_fee_treasury: string;
  total_mei: number;
};

export type QuantumSendResult = {
  hash: string;
  tx_type: number;
  sign_alg: number;
  wire_size: number;
  fee_used: string;
};

export type QuantumTestResult = {
  hash: string;
  fee_used: string;
  metrics: Record<string, unknown>;
};

export const quantumApi = {
  getSettings: () => invoke<QuantumSettings>("quantum_get_settings"),
  setMode: (enabled: boolean) => invoke<void>("quantum_set_mode", { enabled }),
  createPqc: (keystorePassword: string) =>
    invoke<QuantumAccountInfo>("quantum_create_pqc", { keystorePassword }),
  createHybrid: (keystorePassword: string, legacyPrikeyHex?: string) =>
    invoke<QuantumAccountInfo>("quantum_create_hybrid", { keystorePassword, legacyPrikeyHex }),
  importKeystore: (json: string, keystorePassword: string) =>
    invoke<QuantumAccountInfo>("quantum_import_keystore_v3", { json, keystorePassword }),
  exportKeystore: (keystorePassword: string, newPassword?: string) =>
    invoke<string>("quantum_export_keystore_v3", { keystorePassword, newPassword }),
  previewKeystore: (json: string, keystorePassword: string) =>
    invoke<QuantumAccountInfo>("quantum_preview_keystore", { json, keystorePassword }),
  sendType4: (toAddress: string, amountHacash: string, keystorePassword: string) =>
    invoke<QuantumSendResult>("quantum_send_type4", { toAddress, amountHacash, keystorePassword }),
  sendTestTx: (keystorePassword: string) =>
    invoke<QuantumTestResult>("quantum_send_test_tx", { keystorePassword }),
  nodePing: () => invoke<Record<string, unknown>>("quantum_node_ping"),
  balanceProbe: () => invoke<Type4ProbeResult>("quantum_balance_probe"),
  preflightType4: (toAddress: string, amountHacash: string) =>
    invoke<QuantumPreflight>("quantum_preflight_type4", { toAddress, amountHacash }),
  prepareAirgapType4: (toAddress: string, amountHacash: string) =>
    invoke<AirgapPrepareResult>("quantum_prepare_airgap_type4", { toAddress, amountHacash }),
  airgapSignType4: (unsigned: AirgapUnsigned, keystorePassword: string) =>
    invoke<AirgapSignResult>("quantum_airgap_sign_type4", { unsigned, keystorePassword }),
};

export type DappApprovalView = {
  id: string;
  origin: string;
  kind: string;
  title: string;
  summary: string;
  detail: string;
};

export const api = {
  status: () => invoke<WalletStatus>("wallet_status"),
  create: (passphrase: string) => invoke<string>("wallet_create", { passphrase }),
  import: (seed: string, passphrase: string, expectedAddress: string) =>
    invoke<string>("wallet_import", { seed, passphrase, expectedAddress }),
  unlock: (passphrase: string) => invoke<string>("wallet_unlock", { passphrase }),
  lock: () => invoke<void>("wallet_lock"),
  balance: () => invoke<number>("wallet_balance"),
  assetSummary: () => invoke<AssetSummary>("wallet_asset_summary"),
  getSettings: () => invoke<WalletSettings>("wallet_get_settings"),
  updateSettings: (settings: WalletSettings) =>
    invoke<void>("wallet_update_settings", { settings }),
  pingNode: () => invoke<Record<string, unknown>>("wallet_ping_node"),
  pingNodeUrl: (nodeUrl?: string) =>
    invoke<Record<string, unknown>>("wallet_ping_node_url", { nodeUrl: nodeUrl ?? null }),
  fetchAssetPrices: () =>
    invoke<AssetPriceResponse>("wallet_fetch_asset_prices"),
  discoverNodes: () => invoke<NodeDiscoveryReport>("wallet_discover_nodes"),
  nodeCapabilities: () => invoke<NodeCapabilities>("wallet_node_capabilities"),
  inspectAddress: (address: string, networkMode?: "mainnet" | "testnet") =>
    invoke<ParsedAddress>("wallet_inspect_address", {
      address,
      networkMode: networkMode ?? null,
    }),
  inspectTransaction: (bodyHex: string, expectedChainId?: number) =>
    invoke<CanonicalTransaction>("wallet_inspect_transaction", {
      bodyHex,
      expectedChainId: expectedChainId ?? null,
    }),
  resetWallet: (currentPassphrase: string | null, confirmationAddress: string) =>
    invoke<void>("wallet_reset", { currentPassphrase, confirmationAddress }),
  updatePrivacy: (privacy: PrivacySettings) =>
    invoke<void>("wallet_update_privacy_settings", { privacy }),
  txHistory: () => invoke<TxRecord[]>("wallet_tx_history"),
  clearHistory: () => invoke<void>("wallet_clear_tx_history"),
  fastPayStatus: () => invoke<FastPayStatus>("wallet_fast_pay_status"),
  fastPayInbox: () => invoke<FastPayInboxItem[]>("wallet_fast_pay_inbox"),
  acceptFastPay: (paymentId: string) =>
    invoke<FastPayExecution>("wallet_accept_fast_pay", { paymentId }),
  enableFastPay: (depositMei?: number) =>
    invoke<FastPayStatus>("wallet_enable_fast_pay", { depositMei }),
  hubHealth: () => invoke<HubHealth | null>("wallet_hub_health"),
  // hubUrl is what the person has typed but not yet saved. Discovery used to
  // read only the saved setting, so the field the panel told them to paste
  // into was the one thing the scan skipped.
  discoverHubs: (hubUrl?: string) =>
    invoke<HubDiscoveryReport>("wallet_discover_hubs", { hubUrl: hubUrl?.trim() || null }),
  hubDeclaration: (hubUrl: string) =>
    invoke<HubDeclaration>("wallet_hub_declaration", { hubUrl }),
  previewSend: (to: string, amountMei: number, sendOptions?: SendOptions) =>
    invoke<SendPreview>("wallet_preview_send", { to, amountMei, sendOptions }),
  prepareSendHac: (to: string, amountMei: number, sendOptions?: SendOptions) =>
    invoke<PreparedOperationView>("wallet_prepare_send_hac", { to, amountMei, sendOptions }),
  executePreparedHac: (operationId: string) =>
    invoke<SendResult>("wallet_execute_prepared_hac", { operationId }),  sendHac: (to: string, amountMei: number, sendOptions?: SendOptions) =>
    invoke<SendResult>("wallet_send_hac", { to, amountMei, sendOptions }),
  exportBackupToDownloads: (passphrase: string) =>
    invoke<string>("wallet_export_backup_to_downloads", { passphrase }),
  previewBackup: (json: string) => invoke<BackupPreview>("wallet_preview_backup", { json }),
  importBackup: (json: string, passphrase: string, deleteSource?: string | null, allowLegacy = false) =>
    invoke<string>("wallet_import_backup", {
      json,
      passphrase,
      deleteSource: deleteSource ?? null,
      allowLegacy,
    }),
  changePassphrase: (oldPassphrase: string, newPassphrase: string) =>
    invoke<PassphraseChangeOutcome>("wallet_change_passphrase", {
      oldPassphrase,
      newPassphrase,
    }),
  listBillSummaries: () => invoke<BillSummary[]>("wallet_list_bill_summaries"),
  exportBillJson: (paymentId: string) =>
    invoke<string>("wallet_export_bill_json", { paymentId }),
  exportAllBillsJson: () => invoke<string>("wallet_export_all_bills_json"),
  getBillHex: (paymentId: string) => invoke<string>("wallet_get_bill_hex", { paymentId }),
  platformSecurity: () =>
    invoke<PlatformSecurityStatus>("wallet_platform_security_status"),
  confirmBiometric: (operationId: string) =>
    invoke<void>("wallet_confirm_biometric_native", { operationId }),
  biometricUnlockStatus: () =>
    invoke<BiometricUnlockStatus>("wallet_biometric_unlock_status"),
  enableBiometricUnlock: (passphrase: string) =>
    invoke<void>("wallet_enable_biometric_unlock", { passphrase }),
  disableBiometricUnlock: () => invoke<void>("wallet_disable_biometric_unlock"),
  unlockBiometric: () => invoke<string>("wallet_unlock_biometric"),
  platformInfo: () => invoke<{ platform: string; mobile: boolean }>("wallet_platform_info"),
  bumpActivity: () => invoke<void>("wallet_bump_activity"),
  dappConnect: (origin: string) =>
    invoke<{ address?: string; err?: string }>("wallet_dapp_connect", { origin }),
  dappDisconnect: (origin: string) =>
    invoke<{ ok: boolean; disconnected: boolean }>("wallet_dapp_disconnect", { origin }),
  dappHeartbeat: (origin: string) =>
    invoke<{ ok?: boolean; err?: string }>("wallet_dapp_heartbeat", { origin }),
  dappWallet: (origin: string) =>
    invoke<{ address?: string; err?: string }>("wallet_dapp_wallet", { origin }),
  dappTransfer: (origin: string, txobj: string) =>
    invoke<Record<string, unknown>>("wallet_dapp_transfer", { origin, txobj }),
  dappPending: () => invoke<DappApprovalView | null>("wallet_dapp_pending"),
  dappApprove: (id: string) => invoke<void>("wallet_dapp_approve", { id }),
  dappReject: (id: string, reason?: string) =>
    invoke<void>("wallet_dapp_reject", { id, reason: reason ?? null }),
  webviewEval: (label: string, expectedOrigin: string, script: string) =>
    invoke<void>("wallet_webview_eval", { label, expectedOrigin, script }),
  updateDustWhisper: (dustWhisper: DustWhisperSettings) =>
    invoke<void>("wallet_update_dust_whisper_settings", { dustWhisper }),
  whisperRelayHealth: () => invoke<RelayHealthStatus[]>("wallet_whisper_relay_health"),
  queryDiamond: (name: string) => invoke<SharedHacdDiamondInfo>("wallet_query_diamond", { name }),
  listOwnedDiamonds: () => invoke<string[]>("wallet_list_owned_diamonds"),
  previewSendHacd: (to: string, diamondNames: string[]) =>
    invoke<HacdSendPreview>("wallet_preview_send_hacd", { to, diamondNames }),
  prepareSendHacd: (to: string, diamondNames: string[]) =>
    invoke<PreparedOperationView>("wallet_prepare_send_hacd", { to, diamondNames }),
  executePreparedHacd: (operationId: string) =>
    invoke<SendResult>("wallet_execute_prepared_hacd", { operationId }),  sendHacd: (to: string, diamondNames: string[]) =>
    invoke<SendResult>("wallet_send_hacd", { to, diamondNames }),
  channelInfo: () => invoke<ChannelInfo | null>("wallet_channel_info"),
  previewChannelOpen: (hubAddress: string, userDepositMei: string, hubDepositMei: string) =>
    invoke<ChannelSetupPreview>("wallet_preview_channel_open", {
      hubAddress,
      userDepositMei,
      hubDepositMei,
    }),
  prepareChannelOpen: (hubAddress: string, userDepositMei: string, hubDepositMei: string) =>
    invoke<PreparedOperationView>("wallet_prepare_channel_open", { hubAddress, userDepositMei, hubDepositMei }),
  executePreparedChannelOpen: (operationId: string) =>
    invoke<string>("wallet_execute_prepared_channel_open", { operationId }),
  prepareChannelClose: () => invoke<PreparedOperationView>("wallet_prepare_channel_close"),
  executePreparedChannelClose: (operationId: string) =>
    invoke<string>("wallet_execute_prepared_channel_close", { operationId }),
  recoverChannelOpen: () => invoke<string>("wallet_recover_channel_open"),
  recoverChannelClose: () => invoke<string>("wallet_recover_channel_close"),
  openChannel: (hubAddress: string, userDepositMei: number, hubDepositMei: number) =>
    invoke<string>("wallet_open_channel", { hubAddress, userDepositMei, hubDepositMei }),
  closeChannel: () => invoke<string>("wallet_close_channel"),
  importWatchOnly: (address: string) => invoke<string>("wallet_import_watch_only", { address }),
  openWatchOnly: () => invoke<string>("wallet_open_watch_only"),
  setSecurityProfile: (profile: string, currentPassphrase: string) =>
    invoke<void>("wallet_set_security_profile", { profile, currentPassphrase }),
  setSecondFactorThreshold: (amountMei: number | null, currentPassphrase: string) =>
    invoke<void>("wallet_set_second_factor_threshold", { amountMei, currentPassphrase }),
  setMainnetFastPayConsent: (consented: boolean, currentPassphrase: string) =>
    invoke<void>("wallet_set_mainnet_fast_pay_consent", { consented, currentPassphrase }),
  setHardwareMode: (mode: SigningPolicy, currentPassphrase: string) =>
    invoke<void>("wallet_set_hardware_mode", { mode, currentPassphrase }),
  // Cold Vault is irreversible, so it has its own prepared ceremony instead of
  // being reachable through setHardwareMode.
  prepareColdVaultActivation: () =>
    invoke<PreparedOperationView>("wallet_prepare_cold_vault_activation"),
  executePreparedColdVaultActivation: (operationId: string, currentPassphrase: string) =>
    invoke<void>("wallet_execute_prepared_cold_vault_activation", {
      operationId,
      currentPassphrase,
    }),
  queryNativeAssetMetadata: (serial: string) =>
    invoke<NativeAssetMetadata>("wallet_query_native_asset_metadata", { serial }),
  previewSendNativeAsset: (to: string, serial: string, amount: string) =>
    invoke<NativeAssetSendPreview>("wallet_preview_send_native_asset", { to, serial, amount }),
  prepareSendNativeAsset: (to: string, serial: string, amount: string) =>
    invoke<PreparedOperationView>("wallet_prepare_send_native_asset", { to, serial, amount }),
  executePreparedNativeAsset: (operationId: string) =>
    invoke<SendResult>("wallet_execute_prepared_native_asset", { operationId }),
  previewSendBtc: (to: string, satoshi: number) =>
    invoke<BtcSendPreview>("wallet_preview_send_btc", { to, satoshi }),
  prepareSendBtc: (to: string, satoshi: number) =>
    invoke<PreparedOperationView>("wallet_prepare_send_btc", { to, satoshi }),
  executePreparedBtc: (operationId: string) =>
    invoke<SendResult>("wallet_execute_prepared_btc", { operationId }),  sendBtc: (to: string, satoshi: number) =>
    invoke<SendResult>("wallet_send_btc", { to, satoshi }),
  airgapPrepareSend: (to: string, amountMei: number) =>
    invoke<AirgapPrepareResult>("wallet_airgap_prepare_send", { to, amountMei }),
  prepareAirgapSign: (unsigned: AirgapUnsigned) =>
    invoke<PreparedOperationView>("wallet_prepare_airgap_sign", { unsigned }),
  executePreparedAirgapSign: (operationId: string) =>
    invoke<AirgapSignResult>("wallet_execute_prepared_airgap_sign", { operationId }),  airgapSignUnsigned: (unsigned: AirgapUnsigned) =>
    invoke<AirgapSignResult>("wallet_airgap_sign_unsigned", { unsigned }),
  airgapBroadcastSigned: (signed: AirgapSigned) =>
    invoke<SendResult>("wallet_airgap_broadcast_signed", { signed }),
  airgapParseQr: (text: string) => invoke<AirgapParseResult>("wallet_airgap_parse_qr", { text }),
  airgapParseQrBatch: (parts: string[]) =>
    invoke<AirgapParseResult>("wallet_airgap_parse_qr_batch", { parts }),
  checkAppUpdate: (currentVersion: string) =>
    invoke<AppUpdateInfo>("wallet_check_app_update", { currentVersion }),
  downloadAppUpdate: (offerId: string) =>
    invoke<void>("wallet_download_app_update", { offerId }),
  installMobileUpdate: (offerId: string) =>
    invoke<void>("wallet_install_mobile_update", { offerId }),
};

type AppUpdateBase = {
  current_version: string;
  latest_version: string;
  release_notes: string | null;
  release_page: string | null;
  target_os: string;
  target_arch: string;
};

export type AppUpdateInfo = AppUpdateBase &
  (
    | { status: "up_to_date" }
    | { status: "available_untrusted"; release_page: string }
    | { status: "available_manual"; release_page: string }
    | {
        status: "available_trusted";
        release_page: string;
        offer_id: string;
        asset_name: string;
        download_size: number;
      }
  );

export const messengerApi = {
  threads: () => invoke<ChatThread[]>("messenger_threads"),
  messages: (peer: string) => invoke<ChatMessage[]>("messenger_messages", { peer }),
  markRead: (peer: string) => invoke<void>("messenger_mark_read", { peer }),
  /**
   * Whether the next message to this peer is sealed to that peer's own key, and
   * how many messages already in the thread are not known to have been. The
   * screen says nothing about privacy that this answer does not support.
   */
  peerSecurity: (peer: string) =>
    invoke<MessengerPeerSecurity>("messenger_peer_security", { peer }),
  send: (peer: string, body: string, peer_pubkey?: string) =>
    invoke<ChatMessage>("messenger_send", { peer, body, peer_pubkey }),
  /** Reports what the poll reached, not only how many messages it took. */
  pollInbox: () => invoke<MessengerPollOutcome>("messenger_poll_inbox"),
};
