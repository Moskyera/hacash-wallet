pub mod account;
pub mod address;
pub mod airgap;
mod assets;
pub mod authorization;
pub mod bills;
mod biometric_unlock;
pub mod btc_send;
pub mod channel;
pub mod channelpay_interop;
pub mod dapp;
pub mod dust_whisper;
pub mod error;
pub mod fast_pay;
pub mod hacd_send;
pub mod hardware;
pub mod hip23;
pub mod history;
mod http_client;
pub mod hvm_registry_exit;
pub mod hvm_registry_exit_cost;
pub mod hvm_registry_exit_driver;
pub mod hvm_registry_exit_record;
pub mod hvm_registry_open;
pub mod kdf;
pub mod l1_channel_close_safety;
pub mod l1_channel_flow;
pub mod l1_channel_safety;
pub mod l1_fee;
pub mod l2_bill;
pub mod l2_hub;
pub mod l2_safety;
pub mod l2_signer;
mod l2_storage_scope;
pub mod l2_transport;
pub mod messenger;
pub mod messenger_crypto;
pub mod native_asset_metadata;
pub mod native_asset_send;
pub mod node;
pub mod node_capabilities;
pub mod node_discovery;
pub mod paths;
pub mod payment;
pub mod prices;
pub mod privacy;
pub mod protocol_init;
pub mod quantum;
pub mod quantum_vault;
pub mod secure_mem;
pub mod security;
pub mod send_options;
pub mod settings;
pub mod tx_binding;
pub mod type4_fee;
pub mod unlock_guard;
pub mod vault;
pub mod wallet;
pub mod webauthn;

#[cfg(test)]
mod test_support;

pub use address::{
    AddressKind, ParsedAddress, parse_address, require_address_for_network,
    require_agent_payment_recipient,
};
pub use airgap::{
    AirgapEnvelope, AirgapParseResult, AirgapPrepareResult, AirgapSignResult, AirgapSigned,
    AirgapUnsigned,
};
pub use assets::{AssetSummary, DiamondMetadataReader};
pub use bills::BillEntry;
pub use btc_send::{BtcSendPreview, btc_to_satoshi, satoshi_to_btc};
pub use dust_whisper::{DustWhisperSettings, RelayBind, RelayHealthStatus};
pub use error::{WalletError, WalletResult};
pub use fast_pay::{
    DEFAULT_CHANNEL_DEPOSIT_MEI, FastPayState, FastPayStatus, HubDiscoveryEntry, HubDiscoveryReport,
};
pub use hacd_send::{DIAMOND_TRANSFER_FEE_WIRE, HacdSendPreview};
pub use hardware::HardwareSigningMode;
pub use hip23::{BalanceFloorInput, HeightScopeInput, Hip23PatternCheck, Type3CheckInput};
pub use history::TxRecord;
pub use l1_fee::L1FeeTierQuote;
pub use l2_bill::{BillExportBundle, BillProveSummary, BillSignatureStatus, BillSummary};
pub use l2_hub::HubHealth;
pub use messenger::{
    ChatMessage, ChatThread, MessageDirection, MessengerPeerSecurity, MessengerPollOutcome,
};
pub use native_asset_metadata::{NativeAssetMetadata, fetch_native_asset_metadata};
pub use native_asset_send::NativeAssetSendPreview;
pub use node::NativeAssetBalance;
pub use node_capabilities::{
    CapabilitySource, HPAY_LOCAL_PILOT_CHAIN_ID, HPAY_LOCAL_PILOT_NETWORK_KIND,
    HPAY_LOCAL_PILOT_PROFILE_ID, HPAY_MAINNET_MIN_SAFE_HEIGHT, HPAY_MAINNET_NETWORK_KIND,
    HPAY_MAINNET_PROFILE_ID, IstanbulStatus, NodeApiError, NodeCapabilities, NodeChain,
    NodeFeatures, NodeIdentity, NodeLimits, NodeNetworkCapabilities, RegistrySet,
    network_instance_id,
};
pub use prices::{PriceSource, SpotPrices, fetch_spot_prices};
pub use privacy::{PrivacySettings, mask_address, mask_amount, mask_hash};
pub use quantum::{
    QuantumAccountInfo, QuantumAccountSummary, QuantumPreflight, QuantumSendResult,
    QuantumSettings, QuantumTestResult,
};
pub use send_options::{
    DEFAULT_HUB_FEE_MEI, HubFeePayer, L1FeeSpeed, SendFeeBreakdown, SendOptions, SendPreferences,
    WALLET_TREASURY_ADDRESS, fast_pay_fee_breakdown, hac_send_transfer_pairs,
};
pub use settings::QuantumMeta;
pub use settings::WalletSettings;
pub use wallet::{ReviewedSendExpectation, WalletService};
