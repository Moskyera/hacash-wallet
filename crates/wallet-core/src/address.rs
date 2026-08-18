//! Consensus-backed Hacash address classification and wallet network policy.

use field::Address;
use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};

pub const MAINNET: &str = "mainnet";
pub const TESTNET: &str = "testnet";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AddressKind {
    PrivateKey,
    Contract,
    P2sh,
    Pqc,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedAddress {
    pub address: String,
    pub version: u8,
    pub kind: AddressKind,
    pub network_mode: String,
    pub network_allowed: bool,
    pub passive_receive: bool,
    pub fast_pay_eligible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

/// Decode an address with the canonical consensus codec, then apply wallet policy.
/// Unknown network values intentionally fall back to mainnet restrictions.
pub fn parse_address(address: &str, network_mode: &str) -> WalletResult<ParsedAddress> {
    let address = address.trim();
    let decoded = Address::from_readable(address)
        .map_err(|error| WalletError::Transaction(format!("invalid Hacash address: {error}")))?;
    let version = decoded.version();
    let kind = match version {
        Address::PRIVAKEY => AddressKind::PrivateKey,
        Address::CONTRACT => AddressKind::Contract,
        Address::SCRIPTMH => AddressKind::P2sh,
        Address::PQCKEY => AddressKind::Pqc,
        Address::HYBRID => AddressKind::Hybrid,
        _ => {
            return Err(WalletError::Policy(format!(
                "address version {version} is not supported by this wallet"
            )));
        }
    };
    let network_mode = if network_mode.eq_ignore_ascii_case(TESTNET) {
        TESTNET
    } else {
        MAINNET
    };
    let network_allowed = network_mode == TESTNET
        || matches!(
            version,
            Address::PRIVAKEY | Address::CONTRACT | Address::SCRIPTMH
        );
    let passive_receive = version != Address::CONTRACT;
    let fast_pay_eligible = network_allowed && version == Address::PRIVAKEY;
    let warning = match (network_allowed, kind) {
        (false, AddressKind::Pqc | AddressKind::Hybrid) => Some(
            "PQC and hybrid addresses are testnet-only until mainnet support is activated".into(),
        ),
        (true, AddressKind::Contract) => Some(
            "Contract addresses can execute receive hooks and are not passive recipients".into(),
        ),
        (true, AddressKind::P2sh) => {
            Some("P2SH receive is supported on L1, but Fast Pay supports only v0 addresses".into())
        }
        _ => None,
    };

    Ok(ParsedAddress {
        address: decoded.to_readable(),
        version,
        kind,
        network_mode: network_mode.into(),
        network_allowed,
        passive_receive,
        fast_pay_eligible,
        warning,
    })
}

pub fn require_address_for_network(
    address: &str,
    network_mode: &str,
) -> WalletResult<ParsedAddress> {
    let parsed = parse_address(address, network_mode)?;
    if !parsed.network_allowed {
        return Err(WalletError::Policy(parsed.warning.clone().unwrap_or_else(
            || {
                format!(
                    "address version {} is not enabled on {}",
                    parsed.version, parsed.network_mode
                )
            },
        )));
    }
    Ok(parsed)
}

/// A recipient an **agent** may be pointed at with the owner's money.
///
/// # The door this closed
///
/// A reviewer funded a real registry channel on chain with one ordinary
/// Action 1 transfer and no countersignature in existence: the contract's
/// `PayableHAC` accepts any correctly-sized HAC transfer from the left address
/// while the channel is in FUNDING, and this product's ordinary agent payment
/// path builds exactly those bytes for any recipient at all. The three
/// registry-aware funding routes were each gated on the countersigned refund;
/// the generic payment path was never counted, and it was the door that
/// mattered most, because a wallet that cannot fund a channel itself is one
/// whose channels all get funded by hand.
///
/// So an agent payment now has a *narrower* notion of recipient than the chain
/// does: a person or a plain key, never a contract. A contract address is not
/// a passive recipient - `parse_address` already says so, and sets
/// `passive_receive = false` for exactly this reason - and there is no
/// legitimate agent payment in this product whose destination executes code.
/// Putting principal into a contract is its own act, with its own gate
/// (`hacash_wallet_core::hvm_registry_open::authorize_registry_funding`), its
/// own signing boundary and its own durable record.
///
/// The residual is stated rather than implied away: the chain cannot enforce
/// this, and an owner holding their own key can always build such a transfer
/// with some other tool. What is true is that no agent in this app will build
/// it for them.
pub fn require_agent_payment_recipient(
    address: &str,
    network_mode: &str,
) -> WalletResult<ParsedAddress> {
    let parsed = require_address_for_network(address, network_mode)?;
    if parsed.kind == AddressKind::Contract || parsed.version == Address::CONTRACT {
        return Err(WalletError::Policy(
            "an agent payment cannot be sent to a contract address. Contract addresses execute \
             code when they are paid, so this is not a payment to a person; putting money into a \
             contract is a separate action with its own confirmation."
                .into(),
        ));
    }
    if !parsed.passive_receive {
        return Err(WalletError::Policy(
            "an agent payment can only be sent to an address that receives passively".into(),
        ));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fourth funding route, and the reason it is now shut.
    #[test]
    fn an_agent_payment_can_never_be_addressed_to_a_contract() {
        for network_mode in [TESTNET, MAINNET] {
            let contract = readable(Address::CONTRACT);
            assert!(
                require_address_for_network(&contract, network_mode).is_ok(),
                "the chain itself permits this, which is exactly why the wallet has to not"
            );
            assert!(
                require_agent_payment_recipient(&contract, network_mode).is_err(),
                "an agent must not be able to build a transfer into a contract"
            );
            let person = readable(Address::PRIVAKEY);
            require_agent_payment_recipient(&person, network_mode)
                .expect("paying a person is what this path is for");
        }
    }

    fn readable(version: u8) -> String {
        let hash = [version.wrapping_add(1); 20];
        match version {
            Address::PRIVAKEY => Address::create_privakey(hash),
            Address::CONTRACT => Address::create_contract(hash),
            Address::SCRIPTMH => Address::create_scriptmh(hash),
            Address::PQCKEY => Address::create_pqckey(hash),
            Address::HYBRID => Address::create_hybrid(hash),
            _ => unreachable!(),
        }
        .to_readable()
    }

    #[test]
    fn mainnet_accepts_consensus_v0_v1_v5_only() {
        for version in [Address::PRIVAKEY, Address::CONTRACT, Address::SCRIPTMH] {
            let parsed = require_address_for_network(&readable(version), MAINNET).unwrap();
            assert_eq!(parsed.version, version);
            assert!(parsed.network_allowed);
        }
        for version in [Address::PQCKEY, Address::HYBRID] {
            let parsed = parse_address(&readable(version), MAINNET).unwrap();
            assert!(!parsed.network_allowed);
            assert!(require_address_for_network(&readable(version), MAINNET).is_err());
        }
    }

    #[test]
    fn testnet_accepts_istanbul_quantum_address_versions() {
        for version in [Address::PQCKEY, Address::HYBRID] {
            let parsed = require_address_for_network(&readable(version), TESTNET).unwrap();
            assert!(parsed.network_allowed);
            assert!(!parsed.fast_pay_eligible);
        }
    }

    #[test]
    fn only_v0_is_fast_pay_eligible_and_contracts_are_not_passive() {
        let v0 = parse_address(&readable(Address::PRIVAKEY), MAINNET).unwrap();
        let contract = parse_address(&readable(Address::CONTRACT), MAINNET).unwrap();
        let p2sh = parse_address(&readable(Address::SCRIPTMH), MAINNET).unwrap();
        assert!(v0.fast_pay_eligible);
        assert!(v0.passive_receive);
        assert!(!contract.fast_pay_eligible);
        assert!(!contract.passive_receive);
        assert!(!p2sh.fast_pay_eligible);
        assert!(p2sh.passive_receive);
    }

    #[test]
    fn invalid_and_unknown_network_inputs_fail_closed() {
        assert!(parse_address("not-an-address", TESTNET).is_err());
        let pqc = parse_address(&readable(Address::PQCKEY), "unexpected").unwrap();
        assert_eq!(pqc.network_mode, MAINNET);
        assert!(!pqc.network_allowed);
    }
}
