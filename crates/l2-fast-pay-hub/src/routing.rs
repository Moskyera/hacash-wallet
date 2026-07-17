use crate::channel_id::derive_channel_id;
use crate::error::{HubError, HubResult};
use crate::node::{ChannelInfo, ChannelSide, NodeClient};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayeeRoute {
    /// Payee is the other party on the payer's channel.
    SameChannel { side: ChannelSide },
    /// Payee has their own customer↔hub channel.
    CrossChannel {
        channel_id: String,
        side: ChannelSide,
    },
}

pub async fn resolve_payee_route(
    node: &NodeClient,
    hub_address: &str,
    payer_channel: &ChannelInfo,
    payer_channel_id: &str,
    payee: &str,
) -> HubResult<PayeeRoute> {
    if payer_channel.party_side(payee).is_some() {
        return Ok(PayeeRoute::SameChannel {
            side: payer_channel.party_side(payee).expect("checked"),
        });
    }

    let reuse = payer_channel.reuse_version.max(1);
    let candidates = candidate_payee_channel_ids(payee, hub_address, reuse, payer_channel_id);

    for channel_id in candidates {
        let channel = match node.query_channel(&channel_id).await {
            Ok(ch) => ch,
            Err(_) => continue,
        };
        if !channel.is_open() {
            continue;
        }
        if channel.id != channel_id {
            continue;
        }
        if !channel_involves_hub(&channel, hub_address) {
            continue;
        }
        if let Some(side) = channel.party_side(payee) {
            return Ok(PayeeRoute::CrossChannel { channel_id, side });
        }
    }

    Err(HubError::Payment(format!(
        "payee {payee} has no open Fast Pay channel with hub {hub_address}"
    )))
}

fn channel_involves_hub(channel: &ChannelInfo, hub_address: &str) -> bool {
    channel.left.address == hub_address || channel.right.address == hub_address
}

fn candidate_payee_channel_ids(
    payee: &str,
    hub_address: &str,
    reuse_version: u64,
    payer_channel_id: &str,
) -> Vec<String> {
    let mut ids = Vec::new();
    for (left, right) in [(payee, hub_address), (hub_address, payee)] {
        let id = derive_channel_id(left, right, reuse_version);
        if id != payer_channel_id && !ids.contains(&id) {
            ids.push(id);
        }
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{ChannelInfo, ChannelPartyBalance};

    fn sample_channel(id: &str, left: &str, right: &str) -> ChannelInfo {
        ChannelInfo {
            ret: 0,
            id: id.to_owned(),
            status: 0,
            reuse_version: 1,
            left: ChannelPartyBalance {
                address: left.to_owned(),
                hacash: "10".into(),
                satoshi: 0,
            },
            right: ChannelPartyBalance {
                address: right.to_owned(),
                hacash: "0".into(),
                satoshi: 0,
            },
            challenging: None,
        }
    }

    #[test]
    fn candidate_ids_skip_payer_channel_and_try_both_orderings() {
        let payer_id = derive_channel_id("1Alice", "1Hub", 1);
        let ids = candidate_payee_channel_ids("1Bob", "1Hub", 1, &payer_id);
        assert_eq!(ids.len(), 2);
        assert!(!ids.contains(&payer_id));
        assert!(ids.contains(&derive_channel_id("1Bob", "1Hub", 1)));
    }

    #[test]
    fn hub_party_detected_on_channel() {
        let ch = sample_channel("ch1", "1Alice", "1Hub");
        assert_eq!(ch.party_side("1Hub"), Some(ChannelSide::Right));
        assert_eq!(ch.party_side("1Alice"), Some(ChannelSide::Left));
    }
}
