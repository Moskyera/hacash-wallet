//! Exact channel-ledger arithmetic shared by settlement preparation.

use crate::amount::{HacAmount, parse_amount_mei};
use crate::error::{HubError, HubResult};
use crate::node::{ChannelInfo, ChannelSide};
use crate::storage::ChannelLedger;

pub(crate) fn channel_ledger_from_l1(channel: &ChannelInfo) -> HubResult<ChannelLedger> {
    Ok(ChannelLedger {
        left_balance_mei: parse_amount_mei(&channel.left.hacash)?,
        right_balance_mei: parse_amount_mei(&channel.right.hacash)?,
        bill_auto_number: channel.l1_bill_auto_floor(),
    })
}

pub(crate) fn next_bill_auto_number(
    ledger: &ChannelLedger,
    channel: &ChannelInfo,
) -> HubResult<u64> {
    let last = ledger.bill_auto_number.max(channel.l1_bill_auto_floor());
    last.checked_add(1)
        .ok_or_else(|| HubError::State("channel bill number overflow".into()))
}

pub(crate) fn payer_available_mei(ledger: &ChannelLedger, side: ChannelSide) -> HacAmount {
    match side {
        ChannelSide::Left => ledger.left_balance_mei,
        ChannelSide::Right => ledger.right_balance_mei,
    }
}

pub(crate) fn apply_debit(
    ledger: &mut ChannelLedger,
    side: ChannelSide,
    amount_mei: HacAmount,
) -> HubResult<()> {
    let balance = match side {
        ChannelSide::Left => &mut ledger.left_balance_mei,
        ChannelSide::Right => &mut ledger.right_balance_mei,
    };
    *balance = balance.checked_sub(amount_mei)?;
    Ok(())
}

pub(crate) fn apply_credit(
    ledger: &mut ChannelLedger,
    side: ChannelSide,
    amount_mei: HacAmount,
) -> HubResult<()> {
    let balance = match side {
        ChannelSide::Left => &mut ledger.left_balance_mei,
        ChannelSide::Right => &mut ledger.right_balance_mei,
    };
    *balance = balance.checked_add(amount_mei)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{ChannelChallenging, ChannelPartyBalance};

    fn channel(left_hacash: &str, right_hacash: &str, floor: u64) -> ChannelInfo {
        ChannelInfo {
            ret: 0,
            id: "00112233445566778899aabbccddeeff".into(),
            status: crate::node::CHANNEL_STATUS_OPENING,
            open_height: 100,
            close_height: 0,
            reuse_version: 1,
            left: ChannelPartyBalance {
                address: "1Left".into(),
                hacash: left_hacash.into(),
                satoshi: 0,
            },
            right: ChannelPartyBalance {
                address: "1Right".into(),
                hacash: right_hacash.into(),
                satoshi: 0,
            },
            challenging: Some(ChannelChallenging {
                assert_bill_auto_number: floor,
            }),
        }
    }

    #[test]
    fn malformed_l1_balance_fails_closed() {
        let error = channel_ledger_from_l1(&channel("not-an-amount", "0", 0)).unwrap_err();
        assert!(error.to_string().contains("amount"));
    }

    #[test]
    fn bill_number_overflow_fails_closed() {
        let ledger = ChannelLedger {
            left_balance_mei: HacAmount::ZERO,
            right_balance_mei: HacAmount::ZERO,
            bill_auto_number: u64::MAX,
        };
        let error = next_bill_auto_number(&ledger, &channel("0", "0", 0)).unwrap_err();
        assert!(error.to_string().contains("overflow"));
    }
}
