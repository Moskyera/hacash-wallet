mod common;

use common::{audit_gate, with_isolated_wallet_dir};
use hacash_wallet_core::WalletService;
use hacash_wallet_core::paths::wallet_data_root;

#[test]
fn personal_reset_preserves_agent_vault_and_l2_state() {
    audit_gate("personal_reset_preserves_agent_space", || {
        with_isolated_wallet_dir(|| {
            let mut personal = WalletService::new(None, None).unwrap();
            personal.create_wallet("personal-reset-pass-1234").unwrap();

            let agent_root = wallet_data_root()
                .join("agent-wallets")
                .join("wallets")
                .join("agent-test-wallet");
            let agent_l2 = agent_root.join("l2");
            std::fs::create_dir_all(&agent_l2).unwrap();
            let agent_vault = agent_root.join("vault.json");
            let agent_journal = agent_l2.join("channel.journal.enc");
            std::fs::write(&agent_vault, b"agent-vault-sentinel").unwrap();
            std::fs::write(&agent_journal, b"agent-l2-sentinel").unwrap();

            personal.reset_wallet().unwrap();

            assert!(!personal.status().has_wallet);
            assert_eq!(std::fs::read(agent_vault).unwrap(), b"agent-vault-sentinel");
            assert_eq!(std::fs::read(agent_journal).unwrap(), b"agent-l2-sentinel");
        });
    });
}
