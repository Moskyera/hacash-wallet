import { invoke } from "@tauri-apps/api/core";

export type WalletStatus = {
  has_wallet: boolean;
  locked: boolean;
  address: string | null;
  security_profile: string;
  node_url: string;
  l2_enabled: boolean;
};

export type SendPreview = {
  plan: {
    rail: "L2Fast" | "L1OnChain";
    summary: string;
    estimated_fee: string;
  };
  from: string;
  to: string;
  amount_mei: number;
  amount_wire: string;
  fee: string;
};

export type SendResult = {
  rail: "L2Fast" | "L1OnChain";
  tx_hash: string;
  summary: string;
};

export const api = {
  status: () => invoke<WalletStatus>("wallet_status"),
  create: (passphrase: string) => invoke<string>("wallet_create", { passphrase }),
  unlock: (passphrase: string) => invoke<string>("wallet_unlock", { passphrase }),
  lock: () => invoke<void>("wallet_lock"),
  balance: () => invoke<number>("wallet_balance"),
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