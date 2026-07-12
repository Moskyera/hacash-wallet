import { invoke } from "@tauri-apps/api/core";

export type PrivacySettings = {
  hide_balances: boolean;
  hide_addresses: boolean;
  screen_privacy: boolean;
  store_tx_history: boolean;
  clipboard_clear_secs: number;
};

export type HubFeePayer = "sender" | "recipient";

export type SendPreferences = {
  hub_fee_payer: HubFeePayer;
  prefer_fast_pay: boolean;
};

export type SendOptions = {
  hub_fee_payer: HubFeePayer;
  force_l1: boolean;
};

export type SendFeeBreakdown = {
  payer_debit_mei: number;
  recipient_credit_mei: number;
  hub_fee_mei: number | null;
  hub_fee_payer: HubFeePayer;
  l1_fee_wire: string | null;
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

export type WalletSettings = {
  node_url: string;
  l2_hub_url: string | null;
  hub_right_address: string | null;
  channel_id_hex: string | null;
  webauthn_enabled: boolean;
  biometric_send_enabled?: boolean;
  biometric_unlock_enabled?: boolean;
  security_profile: string;
  privacy: PrivacySettings;
  dust_whisper?: DustWhisperSettings;
  send?: SendPreferences;
};

export type WalletStatus = {
  has_wallet: boolean;
  locked: boolean;
  address: string | null;
  security_profile: string;
  node_url: string;
  l2_enabled: boolean;
  fast_pay_state: string;
  fast_pay_message: string;
  watch_only: boolean;
  privacy: PrivacySettings;
  dust_whisper?: DustWhisperSettings;
  seconds_until_lock: number | null;
  channel_id: string | null;
};

export type MessageDirection = "in" | "out";

export type ChatMessage = {
  id: string;
  peer: string;
  direction: MessageDirection;
  body: string;
  timestamp_utc: string;
  delivered: boolean;
};

export type ChatThread = {
  peer: string;
  last_message: string;
  last_timestamp_utc: string;
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

export type HubHealth = {
  ok: boolean;
  version: number;
  name?: string;
  hub_address?: string;
  hub_fee_mei?: number;
};

export type HubDiscoveryEntry = {
  id: string;
  name: string;
  hub_url: string;
  online: boolean;
  hub_address: string | null;
  hub_fee_mei: number | null;
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
  };
  from: string;
  to: string;
  amount_mei: number;
  hip23: Hip23Check;
};

export type SendResult = {
  rail: string;
  tx_hash: string;
  summary: string;
};

export type TxRecord = {
  tx_hash: string;
  rail: string;
  from: string;
  to: string;
  amount_mei: number;
  summary: string;
  timestamp: string;
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
};

export type AssetSummary = {
  hac_mei: number;
  hacd_count: number;
  hacd_names: string[];
  btc_wallet_satoshi: number;
  btc_channel_satoshi: number;
};

export type HacdDiamondInfo = {
  name: string;
  number?: number | null;
  visual_gene?: string | null;
  life_gene?: string | null;
  belong?: string | null;
};

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
  fee_mei: number;
  fee_wire: string;
  hip23: Hip23Check;
  summary: string;
};

export type AirgapUnsigned = {
  v: number;
  from: string;
  to: string;
  amount_mei: number;
  amount_wire: string;
  fee: string;
  body_hex: string;
  summary: string;
  tx_type?: number;
};

export type AirgapSigned = {
  v: number;
  from: string;
  to: string;
  amount_mei: number;
  signed_hex: string;
  summary: string;
  tx_type?: number;
};

export type AirgapEnvelope =
  | (AirgapUnsigned & { kind: "unsigned" })
  | (AirgapSigned & { kind: "signed" });

export type AirgapPrepareResult = {
  envelope: AirgapUnsigned;
  qr_parts: string[];
};

export type AirgapSignResult = {
  envelope: AirgapSigned;
  qr_parts: string[];
};

export type AirgapParseResult = {
  envelope: AirgapEnvelope | null;
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
  balance: () => invoke<number>("quantum_balance"),
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
  import: (seed: string, passphrase: string) =>
    invoke<string>("wallet_import", { seed, passphrase }),
  unlock: (passphrase: string) => invoke<string>("wallet_unlock", { passphrase }),
  lock: () => invoke<void>("wallet_lock"),
  balance: () => invoke<number>("wallet_balance"),
  assetSummary: () => invoke<AssetSummary>("wallet_asset_summary"),
  getSettings: () => invoke<WalletSettings>("wallet_get_settings"),
  updateSettings: (settings: WalletSettings) =>
    invoke<void>("wallet_update_settings", { settings }),
  pingNode: () => invoke<Record<string, unknown>>("wallet_ping_node"),
  resetWallet: () => invoke<void>("wallet_reset"),
  updatePrivacy: (privacy: PrivacySettings) =>
    invoke<void>("wallet_update_privacy_settings", { privacy }),
  txHistory: () => invoke<TxRecord[]>("wallet_tx_history"),
  clearHistory: () => invoke<void>("wallet_clear_tx_history"),
  fastPayStatus: () => invoke<FastPayStatus>("wallet_fast_pay_status"),
  enableFastPay: (depositMei?: number) =>
    invoke<FastPayStatus>("wallet_enable_fast_pay", { depositMei }),
  hubHealth: () => invoke<HubHealth | null>("wallet_hub_health"),
  discoverHubs: () => invoke<HubDiscoveryReport>("wallet_discover_hubs"),
  previewSend: (to: string, amountMei: number, sendOptions?: SendOptions) =>
    invoke<SendPreview>("wallet_preview_send", { to, amountMei, sendOptions }),
  sendHac: (to: string, amountMei: number, sendOptions?: SendOptions) =>
    invoke<SendResult>("wallet_send_hac", { to, amountMei, sendOptions }),
  exportBackup: (passphrase: string) =>
    invoke<string>("wallet_export_backup", { passphrase }),
  exportPrivateKey: (passphrase: string) =>
    invoke<string>("wallet_export_private_key", { passphrase }),
  changePassphrase: (oldPassphrase: string, newPassphrase: string) =>
    invoke<void>("wallet_change_passphrase", { oldPassphrase, newPassphrase }),
  listBillSummaries: () => invoke<BillSummary[]>("wallet_list_bill_summaries"),
  exportBillJson: (paymentId: string) =>
    invoke<string>("wallet_export_bill_json", { paymentId }),
  exportAllBillsJson: () => invoke<string>("wallet_export_all_bills_json"),
  getBillHex: (paymentId: string) => invoke<string>("wallet_get_bill_hex", { paymentId }),
  platformSecurity: () =>
    invoke<PlatformSecurityStatus>("wallet_platform_security_status"),
  confirmBiometric: () => invoke<void>("wallet_confirm_biometric_native"),
  biometricUnlockStatus: () =>
    invoke<BiometricUnlockStatus>("wallet_biometric_unlock_status"),
  enableBiometricUnlock: (passphrase: string) =>
    invoke<void>("wallet_enable_biometric_unlock", { passphrase }),
  disableBiometricUnlock: () => invoke<void>("wallet_disable_biometric_unlock"),
  unlockBiometric: () => invoke<string>("wallet_unlock_biometric"),
  platformInfo: () => invoke<{ platform: string; mobile: boolean }>("wallet_platform_info"),
  updateDustWhisper: (dustWhisper: DustWhisperSettings) =>
    invoke<void>("wallet_update_dust_whisper_settings", { dustWhisper }),
  whisperRelayHealth: () => invoke<RelayHealthStatus[]>("wallet_whisper_relay_health"),
  queryDiamond: (name: string) => invoke<HacdDiamondInfo>("wallet_query_diamond", { name }),
  listOwnedDiamonds: () => invoke<string[]>("wallet_list_owned_diamonds"),
  previewSendHacd: (to: string, diamondNames: string[]) =>
    invoke<HacdSendPreview>("wallet_preview_send_hacd", { to, diamondNames }),
  sendHacd: (to: string, diamondNames: string[]) =>
    invoke<SendResult>("wallet_send_hacd", { to, diamondNames }),
  channelInfo: () => invoke<ChannelInfo | null>("wallet_channel_info"),
  previewChannelOpen: (hubAddress: string, userDepositMei: number, hubDepositMei: number) =>
    invoke<ChannelSetupPreview>("wallet_preview_channel_open", {
      hubAddress,
      userDepositMei,
      hubDepositMei,
    }),
  openChannel: (hubAddress: string, userDepositMei: number, hubDepositMei: number) =>
    invoke<string>("wallet_open_channel", { hubAddress, userDepositMei, hubDepositMei }),
  closeChannel: () => invoke<string>("wallet_close_channel"),
  importWatchOnly: (address: string) => invoke<string>("wallet_import_watch_only", { address }),
  openWatchOnly: () => invoke<string>("wallet_open_watch_only"),
  setSecurityProfile: (profile: string) => invoke<void>("wallet_set_security_profile", { profile }),
  setHardwareMode: (mode: string) => invoke<void>("wallet_set_hardware_mode", { mode }),
  previewSendBtc: (to: string, satoshi: number) =>
    invoke<BtcSendPreview>("wallet_preview_send_btc", { to, satoshi }),
  sendBtc: (to: string, satoshi: number) =>
    invoke<SendResult>("wallet_send_btc", { to, satoshi }),
  webauthnRegisterBegin: (clientOrigin?: string) =>
    invoke<string>("wallet_webauthn_register_begin", {
      clientOrigin: clientOrigin ?? null,
    }),
  webauthnRegisterFinish: (credentialJson: string) =>
    invoke<void>("wallet_webauthn_register_finish", { credentialJson }),
  webauthnAuthBegin: (clientOrigin?: string) =>
    invoke<string>("wallet_webauthn_auth_begin", {
      clientOrigin: clientOrigin ?? null,
    }),
  webauthnAuthFinish: (assertionJson: string) =>
    invoke<void>("wallet_webauthn_auth_finish", { assertionJson }),
  airgapPrepareSend: (to: string, amountMei: number) =>
    invoke<AirgapPrepareResult>("wallet_airgap_prepare_send", { to, amountMei }),
  airgapSignUnsigned: (unsigned: AirgapUnsigned) =>
    invoke<AirgapSignResult>("wallet_airgap_sign_unsigned", { unsigned }),
  airgapBroadcastSigned: (signed: AirgapSigned) =>
    invoke<SendResult>("wallet_airgap_broadcast_signed", { signed }),
  airgapParseQr: (text: string) => invoke<AirgapParseResult>("wallet_airgap_parse_qr", { text }),
  airgapParseQrBatch: (parts: string[]) =>
    invoke<AirgapParseResult>("wallet_airgap_parse_qr_batch", { parts }),
};

export const messengerApi = {
  threads: () => invoke<ChatThread[]>("messenger_threads"),
  messages: (peer: string) => invoke<ChatMessage[]>("messenger_messages", { peer }),
  markRead: (peer: string) => invoke<void>("messenger_mark_read", { peer }),
  send: (peer: string, body: string, peer_pubkey?: string) =>
    invoke<ChatMessage>("messenger_send", { peer, body, peer_pubkey }),
  pollInbox: () => invoke<number>("messenger_poll_inbox"),
};