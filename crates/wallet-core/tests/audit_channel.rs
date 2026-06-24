//! AUDIT-GATE: L2 channel ID & party binding

mod common;

use common::audit_gate;
use hacash_wallet_core::channel::derive_channel_id;

#[test]
fn audit_channel_id_collision_resistance_sample() {
    audit_gate("channel_collision_sample", || {
        let samples = [
            ("1LeftA", "1RightB", 1u64),
            ("1LeftA", "1RightB", 2u64),
            ("1LeftB", "1RightA", 1u64),
        ];
        let ids: Vec<_> = samples.iter().map(|(l, r, v)| derive_channel_id(l, r, *v)).collect();
        for i in 0..ids.len() {
            for j in i + 1..ids.len() {
                assert_ne!(ids[i], ids[j]);
            }
        }
    });
}

#[test]
fn audit_channel_id_hex_charset() {
    audit_gate("channel_hex_charset", || {
        let id = derive_channel_id("1User", "1Hub", 1);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(id.len(), 32);
    });
}