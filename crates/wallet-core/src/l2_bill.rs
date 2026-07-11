use basis::method::verify_signature;
use l2_fast_pay_hub::wire::ChannelPayCompleteDocuments;
use sys::Account;

use crate::account::WalletAccount;
use crate::error::{WalletError, WalletResult};

/// Parse hub bill, co-sign payer slot, return updated hex.
pub fn cosign_bill_hex(bill_hex: &str, account: &WalletAccount) -> WalletResult<String> {
    let mut doc = ChannelPayCompleteDocuments::from_bill_hex(bill_hex)
        .map_err(|e| WalletError::L2(e.to_string()))?;
    let sign = doc
        .chain_payment
        .fill_sign_by_account(account.inner())
        .map_err(|e| WalletError::L2(e.to_string()))?;
    verify_payer_sign(&doc.chain_payment.sign_stuff_hash(), account.inner(), &sign)?;
    Ok(doc.to_bill_hex())
}

fn verify_payer_sign(
    hash: &field::Hash,
    account: &Account,
    sign: &field::Sign,
) -> WalletResult<()> {
    let addr = field::Address::from(*account.address());
    if !verify_signature(hash, &addr, sign) {
        return Err(WalletError::L2("payer bill signature verification failed".into()));
    }
    Ok(())
}