/**
 * A fake Tauri IPC layer, for reviewing the mobile UI in a browser.
 *
 * Same idea and same limits as the desktop harness: fixed answers so the real
 * screens, the real CSS and the real layout render without an Android build.
 * It is not a wallet. Nothing is signed, nothing reaches a node, no key exists,
 * and it refuses to install outside a dev server. preview.html is not part of
 * the production Rollup input, so it is never bundled.
 */

type InvokeArgs = Record<string, unknown> | undefined;

const ADDRESS = "1QGpzAdoDJoCYewETU6mNZmaFfd1By4wD2";

/** Figures near the design mockups, kept internally consistent with the prices below. */
const HAC_BALANCE = 1_020_450.25;
const HACD_COUNT = 45_231;
const BTC_WALLET_SATOSHI = 235_012_500;

const HAC_USD = 0.1494;
const HACD_USD = 1.0;
const BTC_USD = 17_928.62;

const RESPONSES: Record<string, unknown> = {
  wallet_status: {
    has_wallet: true,
    locked: false,
    address: ADDRESS,
    security_profile: "Standard",
    node_url: "https://node.hacash.org",
    network_mode: "mainnet",
    l2_enabled: true,
    l2_hub_url: "https://hub.hacash.org",
    channel_id: "ch_2f9a11",
    webauthn_enabled: false,
    l2_bill_count: 3,
    auto_lock_secs: 900,
    seconds_until_lock: 742,
    hardware_signing_mode: "software",
    require_second_factor_above_mei: 0,
    signing_available: true,
    watch_only: false,
    privacy: {
      hide_balances: false,
      hide_addresses: false,
      screen_privacy: true,
      store_tx_history: true,
      clipboard_clear_secs: 30,
      pause_auto_lock_dapp: true,
    },
    dust_whisper: {
      enabled: false,
      relay_urls: [],
      fallback_direct: true,
      auto_start_relay: false,
    },
    fast_pay_state: "ready",
    fast_pay_message: "Fast Pay channel open and ready to send.",
    legacy_key_derivation: null,
  },

  wallet_asset_summary: {
    hac_mei: HAC_BALANCE,
    hacd_count: HACD_COUNT,
    hacd_names: ["MZTKAA", "XPQRSB", "HHJKLC"],
    btc_wallet_satoshi: BTC_WALLET_SATOSHI,
    btc_channel_satoshi: 0,
    native_assets: [],
  },

  wallet_fetch_asset_prices: {
    hac_usd: HAC_USD,
    hacd_usd: HACD_USD,
    btc_usd: BTC_USD,
    source: "coingecko",
    stale: false,
    observed_at_utc: "2026-08-10T12:04:00Z",
  },

  wallet_tx_history: [
    {
      tx_hash: "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
      rail: "l1",
      from: "1MzNY1oA3kfgYi75zquj3SRUPYztzXHzK9",
      to: ADDRESS,
      amount_mei: 2450,
      summary: "Received from 1MzNY1…zXHzK9",
      timestamp: "2026-08-10 10:24",
      status: "confirmed",
    },
    {
      tx_hash: "b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1",
      rail: "fast_pay",
      from: ADDRESS,
      to: "1FdmvpDsfsPzPTAAKm3xQfzs9YHV3d6XZk",
      amount_mei: 150,
      summary: "Fast Pay to 1Fdmvp…3d6XZk",
      timestamp: "2026-08-10 09:15",
      status: "confirmed",
    },
    {
      tx_hash: "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2",
      rail: "l1",
      from: ADDRESS,
      to: "18fT8iUWkcsJaKrQRVVad6BtRTt3GteZHa",
      amount_mei: 1200,
      summary: "Sent to 18fT8i…3GteZHa",
      timestamp: "2026-08-09 20:47",
      status: "confirmed",
    },
    {
      tx_hash: "d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3",
      rail: "l1",
      from: ADDRESS,
      to: "1LsQXhqCSocLmn1BFCoemvHfrJmvUZmvUZ",
      amount_mei: 500,
      summary: "HIP-20 transfer, 500 USDT",
      timestamp: "2026-08-09 18:33",
      status: "pending",
    },
  ],

  wallet_fast_pay_status: {
    state: "ready",
    message: "Fast Pay channel open and ready to send.",
  },

  wallet_get_settings: {
    node_url: "https://node.hacash.org",
    fallback_urls: [],
    auto_failover: true,
  },

  wallet_platform_security_status: {
    native_biometric_available: true,
    platform: "android",
  },

  wallet_biometric_unlock_status: {
    enabled: false,
    available: true,
  },

  wallet_dapp_wallet: ADDRESS,

  // One approval or null, never a list: an empty array reads as truthy and
  // renders the approval sheet against a request that is not there.
  wallet_dapp_pending: null,
};

function fallback(command: string): unknown {
  if (/^plugin:\w+\|get_all_/.test(command)) return [];
  if (command.startsWith("plugin:event|")) return 0;
  if (/(_list|_history|_bills|_inbox|summaries|discover|_threads|_messages)/.test(command)) {
    return [];
  }
  return null;
}

export function installPreviewIpc(): void {
  if (!import.meta.env.DEV) {
    throw new Error("The preview IPC mock must never load outside a dev server.");
  }

  const globalWindow = window as unknown as Record<string, unknown>;
  let nextCallbackId = 1;
  const callbacks = new Map<number, (payload: unknown) => void>();

  globalWindow.__TAURI_INTERNALS__ = {
    invoke: async (command: string, args: InvokeArgs) => {
      const known = Object.prototype.hasOwnProperty.call(RESPONSES, command);
      console.info(
        `[preview ipc] ${command}${known ? "" : " (no fixture, empty reply)"}`,
        args ?? {},
      );
      return known ? RESPONSES[command] : fallback(command);
    },
    transformCallback: (callback: (payload: unknown) => void) => {
      const id = nextCallbackId++;
      callbacks.set(id, callback);
      return id;
    },
    metadata: { currentWindow: { label: "main" }, currentWebview: { label: "main" } },
    plugins: {},
  };

  globalWindow.__TAURI_EVENT_PLUGIN_INTERNALS__ = {
    unregisterListener: (_event: string, id: number) => {
      callbacks.delete(id);
      return Promise.resolve();
    },
  };
}

export function seedPreviewPriceCache(): void {
  window.localStorage.setItem(
    "hacash.wallet.asset-prices.v1",
    JSON.stringify({
      version: 1,
      prices: {
        hacUsd: HAC_USD,
        hacdUsd: HACD_USD,
        btcUsd: BTC_USD,
        source: "coingecko",
        stale: false,
        observedAtUtc: new Date().toISOString(),
      },
    }),
  );
}
