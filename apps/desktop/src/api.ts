import { invoke } from "@tauri-apps/api/core";

export type PrivacySettings = {
  hide_balances: boolean;
  hide_addresses: boolean;
  screen_privacy: boolean;
  store_tx_history: boolean;
  clipboard_clear_secs: number;
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
  state: "ready" | "needs_channel" | "hub_unreachable" | "no_provider";
  message: string;
  provider_name: string | null;
  hub_url: string | null;
  can_enable: boolean;
  default_deposit_mei: number;
};

export type WalletStatus = {
  has_wallet: boolean;
  locked: boolean;
  address: string | null;
  security_profile: string;
  node_url: string;
  l2_enabled: boolean;
  l2_hub_url: string | null;
  channel_id: string | null;
  webauthn_enabled: boolean;
  l2_bill_count: number;
  auto_lock_secs: number;
  seconds_until_lock: number | null;
  hardware_signing_mode: string;
  watch_only: boolean;
  privacy: PrivacySettings;
  dust_whisper: DustWhisperSettings;
  fast_pay_state: FastPayStatus["state"];
  fast_pay_message: string;
}

export type PlatformSecurityStatus = {
  native_biometric_available: boolean;
  platform: string;
};

export type WalletSettings = {
  node_url: string;
  l2_hub_url: string | null;
  hub_right_address: string | null;
  channel_id_hex: string | null;
  webauthn_enabled: boolean;
  security_profile: string;
  privacy: PrivacySettings;
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
  };
  from: string;
  to: string;
  amount_mei: number;
  amount_wire: string;
  fee: string;
  hip23: Hip23Check;
  fast_pay: FastPayStatus;
};

export type SendResult = {
  rail: "L2Fast" | "L1OnChain" | "QuantumType4";
  tx_hash: string;
  summary: string;
};

export type ChannelSetupPreview = {
  channel_id: string;
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

export type TxRecord = {
  tx_hash: string;
  rail: string;
  from: string;
  to: string;
  amount_mei: number;
  summary: string;
  timestamp: string;
};

export type HubHealth = {
  ok: boolean;
  version: number;
  name?: string;
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
  | {
      kind: "unsigned";
      v: number;
      from: string;
      to: string;
      amount_mei: number;
      amount_wire: string;
      fee: string;
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
      signed_hex: string;
      summary: string;
      tx_type?: number;
    };

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
  exportBackup: (passphrase: string) =>
    invoke<string>("wallet_export_backup", { passphrase }),
  changePassphrase: (oldPassphrase: string, newPassphrase: string) =>
    invoke<void>("wallet_change_passphrase", { oldPassphrase, newPassphrase }),
  unlock: (passphrase: string) => invoke<string>("wallet_unlock", { passphrase }),
  lock: () => invoke<void>("wallet_lock"),
  balance: () => invoke<number>("wallet_balance"),
  getSettings: () => invoke<WalletSettings>("wallet_get_settings"),
  updateSettings: (settings: WalletSettings) =>
    invoke<void>("wallet_update_settings", { settings }),
  webauthnRegisterBegin: () => invoke<string>("wallet_webauthn_register_begin"),
  webauthnRegisterFinish: (credentialJson: string) =>
    invoke<void>("wallet_webauthn_register_finish", { credentialJson }),
  webauthnAuthBegin: () => invoke<string>("wallet_webauthn_auth_begin"),
  webauthnAuthFinish: (assertionJson: string) =>
    invoke<void>("wallet_webauthn_auth_finish", { assertionJson }),
  hubHealth: () => invoke<HubHealth | null>("wallet_hub_health"),
  fastPayStatus: () => invoke<FastPayStatus>("wallet_fast_pay_status"),
  enableFastPay: (depositMei?: number) =>
    invoke<FastPayStatus>("wallet_enable_fast_pay", { depositMei: depositMei ?? null }),
  listBills: () => invoke<BillEntry[]>("wallet_list_bills"),
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
  previewChannelOpen: (hubAddress: string, userDepositMei: number, hubDepositMei: number) =>
    invoke<ChannelSetupPreview>("wallet_preview_channel_open", {
      hubAddress,
      userDepositMei,
      hubDepositMei,
    }),
  openChannel: (hubAddress: string, userDepositMei: number, hubDepositMei: number) =>
    invoke<string>("wallet_open_channel", {
      hubAddress,
      userDepositMei,
      hubDepositMei,
    }),
  closeChannel: () => invoke<string>("wallet_close_channel"),
  previewSend: (to: string, amountMei: number) =>
    invoke<SendPreview>("wallet_preview_send", { to, amountMei }),
  platformSecurityStatus: () =>
    invoke<PlatformSecurityStatus>("wallet_platform_security_status"),
  confirmBiometricNative: () => invoke<void>("wallet_confirm_biometric_native"),
  importWatchOnly: (address: string) => invoke<string>("wallet_import_watch_only", { address }),
  openWatchOnly: () => invoke<string>("wallet_open_watch_only"),
  setHardwareMode: (mode: string) => invoke<void>("wallet_set_hardware_mode", { mode }),
  sendHac: (to: string, amountMei: number) =>
    invoke<SendResult>("wallet_send_hac", { to, amountMei }),
  setSecurityProfile: (profile: string) =>
    invoke<void>("wallet_set_security_profile", { profile }),
  updatePrivacySettings: (privacy: PrivacySettings) =>
    invoke<void>("wallet_update_privacy_settings", { privacy }),
  updateDustWhisperSettings: (dustWhisper: DustWhisperSettings) =>
    invoke<void>("wallet_update_dust_whisper_settings", { dustWhisper }),
  whisperRelayHealth: () =>
    invoke<RelayHealthStatus[]>("wallet_whisper_relay_health"),
  clearTxHistory: () => invoke<void>("wallet_clear_tx_history"),
  airgapPrepareSend: (to: string, amountMei: number) =>
    invoke<AirgapPrepareResult>("wallet_airgap_prepare_send", { to, amountMei }),
  airgapSignUnsigned: (unsigned: AirgapUnsigned) =>
    invoke<AirgapSignResult>("wallet_airgap_sign_unsigned", { unsigned }),
  airgapBroadcastSigned: (signed: AirgapSigned) =>
    invoke<SendResult>("wallet_airgap_broadcast_signed", { signed }),
  airgapParseQr: (text: string) =>
    invoke<AirgapParseResult>("wallet_airgap_parse_qr", { text }),
  airgapParseQrBatch: (parts: string[]) =>
    invoke<AirgapParseResult>("wallet_airgap_parse_qr_batch", { parts }),
};