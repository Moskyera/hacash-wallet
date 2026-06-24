import { invoke } from "@tauri-apps/api/core";

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
};

export type WalletSettings = {
  node_url: string;
  l2_hub_url: string | null;
  hub_right_address: string | null;
  channel_id_hex: string | null;
  webauthn_enabled: boolean;
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
    channel_id?: string | null;
  };
  from: string;
  to: string;
  amount_mei: number;
  amount_wire: string;
  fee: string;
  hip23: Hip23Check;
};

export type SendResult = {
  rail: "L2Fast" | "L1OnChain";
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

export const api = {
  status: () => invoke<WalletStatus>("wallet_status"),
  create: (passphrase: string) => invoke<string>("wallet_create", { passphrase }),
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
  previewSend: (to: string, amountMei: number) =>
    invoke<SendPreview>("wallet_preview_send", { to, amountMei }),
  sendHac: (to: string, amountMei: number, biometricOk: boolean, yubikeyOk: boolean) =>
    invoke<SendResult>("wallet_send_hac", {
      to,
      amountMei,
      biometricOk,
      yubikeyOk,
    }),
  setSecurityProfile: (profile: string) =>
    invoke<void>("wallet_set_security_profile", { profile }),
};