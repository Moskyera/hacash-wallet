//! STRESS: Channel ID derivation under parallel load

mod common;

use common::stress_gate;
use hacash_wallet_core::channel::derive_channel_id;
use std::thread;

const THREADS: usize = 8;
const PER_THREAD: usize = 2500;

#[test]
fn stress_channel_derive_parallel_20k() {
    stress_gate("channel_parallel_20k", || {
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                thread::spawn(move || {
                    for i in 0..PER_THREAD {
                        let left = format!("1Left{t}_{i}");
                        let right = format!("1Right{t}_{i}");
                        let id = derive_channel_id(&left, &right, i as u64);
                        assert_eq!(id.len(), 32);
                        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread panicked");
        }
    });
}
