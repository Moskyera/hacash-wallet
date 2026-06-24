//! Exponential backoff after failed unlock attempts (Bitcoin-class brute-force mitigation).

use std::time::{Duration, Instant};

use crate::error::{WalletError, WalletResult};

const BASE_DELAY_MS: u64 = 1_000;
const MAX_DELAY_MS: u64 = 300_000;

#[derive(Debug, Default)]
pub struct UnlockGuard {
    failures: u32,
    locked_until: Option<Instant>,
}

impl UnlockGuard {
    pub fn check_allowed(&self) -> WalletResult<()> {
        if let Some(until) = self.locked_until {
            if Instant::now() < until {
                let secs = (until - Instant::now()).as_secs().max(1);
                return Err(WalletError::UnlockRateLimited(secs));
            }
        }
        Ok(())
    }

    pub fn record_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
        let shift = self.failures.saturating_sub(1).min(8);
        let delay_ms = (BASE_DELAY_MS.saturating_mul(1 << shift)).min(MAX_DELAY_MS);
        self.locked_until = Some(Instant::now() + Duration::from_millis(delay_ms));
    }

    pub fn record_success(&mut self) {
        self.failures = 0;
        self.locked_until = None;
    }

    #[doc(hidden)]
    pub fn audit_failures(&self) -> u32 {
        self.failures
    }
}