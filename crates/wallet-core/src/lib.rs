pub mod account;
pub mod airgap;
pub mod bills;
pub mod channel;
pub mod error;
pub mod history;
pub mod hardware;
pub mod hip23;
pub mod kdf;
pub mod secure_mem;
pub mod l2_hub;
pub mod node;
pub mod paths;
pub mod payment;
pub mod protocol_init;
pub mod privacy;
pub mod security;
pub mod settings;
pub mod quantum;
pub mod quantum_vault;
pub mod unlock_guard;
pub mod vault;
pub mod wallet;
pub mod webauthn;

pub use airgap::{
    AirgapEnvelope, AirgapParseResult, AirgapPrepareResult, AirgapSignResult, AirgapSigned,
    AirgapUnsigned,
};
pub use bills::BillEntry;
pub use error::{WalletError, WalletResult};
pub use history::TxRecord;
pub use hip23::{Hip23PatternCheck, Type3CheckInput, HeightScopeInput, BalanceFloorInput};
pub use l2_hub::HubHealth;
pub use hardware::HardwareSigningMode;
pub use privacy::{mask_address, mask_amount, mask_hash, PrivacySettings};
pub use settings::WalletSettings;
pub use quantum::{
    QuantumAccountInfo, QuantumAccountSummary, QuantumPreflight, QuantumSendResult, QuantumSettings,
    QuantumTestResult, TEST_LEGACY_RECIPIENT, TYPE4_AUTO_FEE,
};
pub use settings::QuantumMeta;
pub use wallet::WalletService;