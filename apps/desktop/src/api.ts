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

export type FastPayStatus = {
  state:
    | "ready"
    | "needs_channel"
    | "hub_unreachable"
    | "checking"
    | "provider_incompatible"
    | "no_provider";
  message: string;
  provider_name: string | null;
  hub_url: string | null;
  can_enable: boolean;
  default_deposit_mei: number;
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

export type SigningPolicy = "software" | "webauthn_gate" | "airgap_only" | "watch_only";

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
  l2_hub_url: string | null;
  channel_id: string | null;
  webauthn_enabled: boolean;
  l2_bill_count: number;
  auto_lock_secs: number;
  seconds_until_lock: number | null;
  hardware_signing_mode: SigningPolicy;
  require_second_factor_above_mei: number;
  signing_available: boolean;
  watch_only: boolean;
  privacy: PrivacySettings;
  dust_whisper: DustWhisperSettings;
  fast_pay_state: FastPayStatus["state"];
  fast_pay_message: string;
  /** Non-null when the key was derived from a guessable phrase. */
  legacy_key_derivation: string | null;
}

export type PlatformSecurityStatus = {
  native_biometric_available: boolean;
  platform: string;
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
  security_profile: string;
  hardware_signing_mode: SigningPolicy;
  require_second_factor_above_mei?: number | null;
  privacy: PrivacySettings;
  send?: SendPreferences;
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
};

export type Hip23Check = {
  ok: boolean;
  warnings: string[];
  errors: string[];
};

export type Hip23PatternCheck = {
  pattern: string;
  check: Hip23Check;
};

export type SendPreview = {
  plan: {
    rail: "L2Fast" | "L1OnChain";
    summary: string;
    estimated_fee: string;
    channel_id?: string | null;
    rail_label: string;
    rail_detail: string;
    fee_breakdown: SendFeeBreakdown;
    l1_fee_tiers?: L1FeeTierQuote[];
    // Set when the wallet had Fast Pay set up for this send and chose
    // not to use it. The blockchain fallback is correct; doing it in
    // silence was not.
    fast_pay_declined?: string | null;
  };
  from: string;
  to: string;
  amount_mei: number;
  amount_wire: string;
  fee: string;
  service_fee_mei: number;
  service_fee_treasury: string | null;
  hip23: Hip23Check;
  fast_pay: FastPayStatus;
  send_options: SendOptions;
};

export type ReviewedSendExpectation = {
  from: string;
  to: string;
  amount_wire: string;
  rail: "L2Fast" | "L1OnChain";
  channel_id?: string | null;
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
  rail: "L2Fast" | "L1OnChain" | "QuantumType4";
  tx_hash: string;
  summary: string;
  pending: boolean;
};

export type ChannelSetupPreview = {
  channel_id: string;
  reuse_version: number;
  left_address: string;
  right_address: string;
  left_deposit: string;
  right_deposit: string;
};

export type ChannelInfo = {
  id: string;
  status: number;
  left: { address: string; hacash: string };
  right: { address: string; hacash: string };
};

export type BillEntry = {
  payment_id: string;
  bill_hex: string;
};

export type BillSignatureStatus = {
  address: string;
  filled: boolean;
  verified: boolean;
};

export type BillProveSummary = {
  channel_id_hex: string;
  bill_auto_number: number;
  pay_amount_mei: string;
  pay_direction: string;
  left_balance_mei: string;
  right_balance_mei: string;
  left_address: string;
  right_address: string;
};

export type BillSummary = {
  payment_id: string;
  timestamp_unix: number;
  timestamp_utc: string;
  channel_legs: number;
  hex_byte_length: number;
  prove_bodies: BillProveSummary[];
  signatures: BillSignatureStatus[];
  all_signatures_filled: boolean;
  all_signatures_verified: boolean;
  dispute_ready: boolean;
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
  | {
      kind: "unsigned";
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
    }
  | {
      kind: "signed";
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

export type QuantumAccountInfo = {
  kind: string;
  address: string;
  address_version: number;
  alg_id: number;
  mldsa_pubkey: string;
  secp_pubkey: string;
};

/** Display/send identity from settings or mapped from a full account unlock. */
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

export type AssetSummary = import("@hacash/wallet-ui").AssetSummary;
export type NativeAssetSendPreview = import("@hacash/wallet-ui").NativeAssetSendPreview;
export type NativeAssetMetadata = import("@hacash/wallet-ui").NativeAssetMetadata;

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

export const quantumApi = {
  getSettings: () => invoke<QuantumSettings>("quantum_get_settings"),
  setMode: (enabled: boolean) => invoke<void>("quantum_set_mode", { enabled }),
  createPqc: (keystorePassword: string) =>
    invoke<QuantumAccountInfo>("quantum_create_pqc", { keystorePassword }),
  createHybrid: (keystorePassword: string, legacyPrikeyHex?: string) =>
    invoke<QuantumAccountInfo>("quantum_create_hybrid", { keystorePassword, legacyPrikeyHex }),
  createHybridFromPrivakey: (legacyPrikeyHex: string, keystorePassword: string) =>
    invoke<QuantumAccountInfo>("quantum_create_hybrid_from_privakey", {
      legacyPrikeyHex,
      keystorePassword,
    }),
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

export const api = {
  status: () => invoke<WalletStatus>("wallet_status"),
  create: (passphrase: string) => invoke<string>("wallet_create", { passphrase }),
  import: (seed: string, passphrase: string, expectedAddress: string) =>
    invoke<string>("wallet_import", { seed, passphrase, expectedAddress }),
  exportBackup: (passphrase: string) =>
    invoke<string>("wallet_export_backup", { passphrase }),
  previewBackup: (json: string) => invoke<BackupPreview>("wallet_preview_backup", { json }),
  importBackup: (json: string, passphrase: string, deleteSource?: string | null, allowLegacy = false) =>
    invoke<string>("wallet_import_backup", {
      json,
      passphrase,
      deleteSource: deleteSource ?? null,
      allowLegacy,
    }),
  changePassphrase: (oldPassphrase: string, newPassphrase: string) =>
    invoke<void>("wallet_change_passphrase", { oldPassphrase, newPassphrase }),
  unlock: (passphrase: string) => invoke<string>("wallet_unlock", { passphrase }),
  lock: () => invoke<void>("wallet_lock"),
  balance: () => invoke<number>("wallet_balance"),
  assetSummary: () => invoke<AssetSummary>("wallet_asset_summary"),
  getSettings: () => invoke<WalletSettings>("wallet_get_settings"),
  updateSettings: (settings: WalletSettings) =>
    invoke<void>("wallet_update_settings", { settings }),
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
  fetchAssetPrices: () =>
    invoke<AssetPriceResponse>("wallet_fetch_asset_prices"),
  webauthnRegisterBegin: (clientOrigin?: string) =>
    invoke<string>("wallet_webauthn_register_begin", { clientOrigin: clientOrigin ?? null }),
  webauthnRegisterFinish: (credentialJson: string, currentPassphrase: string) =>
    invoke<void>("wallet_webauthn_register_finish", {
      credentialJson,
      currentPassphrase,
    }),
  // Replacing a registered authenticator needs the outgoing one to approve.
  webauthnReplacementBegin: (clientOrigin?: string) =>
    invoke<string>("wallet_webauthn_replacement_begin", { clientOrigin: clientOrigin ?? null }),
  webauthnReplacementFinish: (assertionJson: string) =>
    invoke<void>("wallet_webauthn_replacement_finish", { assertionJson }),
  webauthnAuthBegin: (operationId: string, clientOrigin?: string) =>
    invoke<string>("wallet_webauthn_auth_begin", { operationId, clientOrigin: clientOrigin ?? null }),
  webauthnAuthFinish: (operationId: string, assertionJson: string) =>
    invoke<void>("wallet_webauthn_auth_finish", { operationId, assertionJson }),
  hubHealth: () => invoke<HubHealth | null>("wallet_hub_health"),
  discoverHubs: () => invoke<HubDiscoveryReport>("wallet_discover_hubs"),
  fastPayStatus: () => invoke<FastPayStatus>("wallet_fast_pay_status"),
  enableFastPay: (depositMei?: number) =>
    invoke<FastPayStatus>("wallet_enable_fast_pay", { depositMei: depositMei ?? null }),
  listBills: () => invoke<BillEntry[]>("wallet_list_bills"),
  fastPayInbox: () => invoke<FastPayInboxItem[]>("wallet_fast_pay_inbox"),
  acceptFastPay: (paymentId: string) =>
    invoke<FastPayExecution>("wallet_accept_fast_pay", { paymentId }),
  listBillSummaries: () => invoke<BillSummary[]>("wallet_list_bill_summaries"),
  exportBillJson: (paymentId: string) =>
    invoke<string>("wallet_export_bill_json", { paymentId }),
  exportAllBillsJson: () => invoke<string>("wallet_export_all_bills_json"),
  getBillHex: (paymentId: string) => invoke<string>("wallet_get_bill_hex", { paymentId }),
  txHistory: () => invoke<TxRecord[]>("wallet_tx_history"),
  validateHip23: (
    universal: Record<string, unknown>,
    p2?: Record<string, unknown> | null,
    p3?: Record<string, unknown> | null,
  ) => invoke<Hip23PatternCheck[]>("wallet_validate_hip23", { universal, p2, p3 }),
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
    invoke<string>("wallet_open_channel", {
      hubAddress,
      userDepositMei,
      hubDepositMei,
    }),
  closeChannel: () => invoke<string>("wallet_close_channel"),
  previewSend: (to: string, amountMei: number, sendOptions?: SendOptions) =>
    invoke<SendPreview>("wallet_preview_send", { to, amountMei, sendOptions }),
  platformSecurityStatus: () =>
    invoke<PlatformSecurityStatus>("wallet_platform_security_status"),
  confirmBiometricNative: (operationId: string) =>
    invoke<void>("wallet_confirm_biometric_native", { operationId }),
  importWatchOnly: (address: string) => invoke<string>("wallet_import_watch_only", { address }),
  openWatchOnly: () => invoke<string>("wallet_open_watch_only"),
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
  prepareSendHac: (to: string, amountMei: number, sendOptions?: SendOptions) =>
    invoke<PreparedOperationView>("wallet_prepare_send_hac", { to, amountMei, sendOptions }),
  executePreparedHac: (operationId: string) =>
    invoke<SendResult>("wallet_execute_prepared_hac", { operationId }),
  sendHac: (
    to: string,
    amountMei: number,
    sendOptions?: SendOptions,
    reviewed?: ReviewedSendExpectation,
  ) => invoke<SendResult>("wallet_send_hac", { to, amountMei, sendOptions, reviewed }),
  setSecurityProfile: (profile: string, currentPassphrase: string) =>
    invoke<void>("wallet_set_security_profile", { profile, currentPassphrase }),
  setSecondFactorThreshold: (amountMei: number | null, currentPassphrase: string) =>
    invoke<void>("wallet_set_second_factor_threshold", { amountMei, currentPassphrase }),
  setMainnetFastPayConsent: (consented: boolean, currentPassphrase: string) =>
    invoke<void>("wallet_set_mainnet_fast_pay_consent", { consented, currentPassphrase }),
  updatePrivacySettings: (privacy: PrivacySettings) =>
    invoke<void>("wallet_update_privacy_settings", { privacy }),
  updateDustWhisperSettings: (dustWhisper: DustWhisperSettings) =>
    invoke<void>("wallet_update_dust_whisper_settings_desktop", { dustWhisper }),
  whisperRelayHealth: () =>
    invoke<RelayHealthStatus[]>("wallet_whisper_relay_health"),
  clearTxHistory: () => invoke<void>("wallet_clear_tx_history"),
  airgapPrepareSend: (to: string, amountMei: number) =>
    invoke<AirgapPrepareResult>("wallet_airgap_prepare_send", { to, amountMei }),
  prepareAirgapSign: (unsigned: AirgapUnsigned) =>
    invoke<PreparedOperationView>("wallet_prepare_airgap_sign", { unsigned }),
  executePreparedAirgapSign: (operationId: string) =>
    invoke<AirgapSignResult>("wallet_execute_prepared_airgap_sign", { operationId }),  airgapSignUnsigned: (unsigned: AirgapUnsigned) =>
    invoke<AirgapSignResult>("wallet_airgap_sign_unsigned", { unsigned }),
  airgapBroadcastSigned: (signed: AirgapSigned) =>
    invoke<SendResult>("wallet_airgap_broadcast_signed", { signed }),
  airgapParseQr: (text: string) =>
    invoke<AirgapParseResult>("wallet_airgap_parse_qr", { text }),
  airgapParseQrBatch: (parts: string[]) =>
    invoke<AirgapParseResult>("wallet_airgap_parse_qr_batch", { parts }),
  queryDiamond: (name: string) => invoke<SharedHacdDiamondInfo>("wallet_query_diamond", { name }),
  listOwnedDiamonds: () => invoke<string[]>("wallet_list_owned_diamonds"),
  previewSendHacd: (to: string, diamondNames: string[]) =>
    invoke<HacdSendPreview>("wallet_preview_send_hacd", { to, diamondNames }),
  prepareSendHacd: (to: string, diamondNames: string[]) =>
    invoke<PreparedOperationView>("wallet_prepare_send_hacd", { to, diamondNames }),
  executePreparedHacd: (operationId: string) =>
    invoke<SendResult>("wallet_execute_prepared_hacd", { operationId }),  sendHacd: (to: string, diamondNames: string[]) =>
    invoke<SendResult>("wallet_send_hacd", { to, diamondNames }),
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
  bumpActivity: () => invoke<void>("wallet_bump_activity"),
  dappConnect: (origin: string) =>
    invoke<{ address?: string; err?: string }>("wallet_dapp_connect", { origin }),
  dappDisconnect: (origin: string) =>
    invoke<{ ok: boolean; disconnected: boolean }>("wallet_dapp_disconnect", { origin }),
  dappHeartbeat: (origin: string) =>
    invoke<{ ok?: boolean; err?: string }>("wallet_dapp_heartbeat", { origin }),
  dappWallet: (origin: string) =>
    invoke<{ address?: string; err?: string }>("wallet_dapp_wallet", { origin }),
  dappPending: () =>
    invoke<DappApprovalView | null>("wallet_dapp_pending"),
  dappApprove: (id: string) => invoke<void>("wallet_dapp_approve", { id }),
  dappReject: (id: string, reason?: string) =>
    invoke<void>("wallet_dapp_reject", { id, reason: reason ?? null }),
  webviewEval: (label: string, expectedOrigin: string, script: string) =>
    invoke<void>("wallet_webview_eval", { label, expectedOrigin, script }),
  checkAppUpdate: (currentVersion: string) =>
    invoke<AppUpdateInfo>("wallet_check_app_update", { currentVersion }),
  downloadAppUpdate: (offerId: string) =>
    invoke<void>("wallet_download_app_update", { offerId }),
  installDesktopUpdate: (offerId: string) =>
    invoke<void>("wallet_install_desktop_update", { offerId }),
};

export type DappApprovalView = {
  id: string;
  origin: string;
  kind: string;
  title: string;
  summary: string;
  detail: string;
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
