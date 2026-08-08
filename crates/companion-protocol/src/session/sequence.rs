//! The desktop side of the `challenge_sequence` contract.
//!
//! `SessionChallenge::challenge_sequence` is not a random identifier. The phone
//! feeds it straight into its durable anti-replay guard as the sequence of the
//! `companion_session_challenge` scope (see [`crate::replay::ReplayGuard::check`]),
//! which accepts a message only when `sequence > last accepted sequence` for that
//! scope. The field is therefore a **strictly increasing counter owned by the
//! desktop**, and any desktop that draws it independently per handshake breaks
//! the contract: once one handshake lands on a high value, every later handshake
//! that draws lower is refused as a replay until the scope expires.
//!
//! This type is the counter the contract asks for. It is monotone within a
//! process, monotone across restarts as long as the wall clock is, and it needs
//! no durable write on the unauthenticated challenge phase, which is the
//! constraint that pushed the original implementation to a random draw.
//!
//! ## Why a time-composite is not a weakening
//!
//! `challenge_sequence` never carried unpredictability. The challenge's
//! unpredictability lives in the 32-byte `challenge_nonce` and, after the
//! handshake, in the 16-byte session random; both are untouched here, and the
//! guard's separate nonce check is untouched too. The seconds component is also
//! not a disclosure: `issued_at` already carries the same second in the clear
//! and is covered by the same signature. What changes is only that the counter
//! now satisfies the ordering the peer verifies.

use crate::error::{CompanionError, CompanionResult};

/// Sub-second room inside one wall-clock second.
///
/// A second of handshakes can allocate 2^20 sequences before the counter runs
/// ahead of the clock, and the clock component still has room for wall-clock
/// times far past any plausible deployment (`u64::MAX / 2^20` seconds is
/// ~557,000 years).
const SEQUENCES_PER_SECOND: u64 = 1 << 20;

/// Strictly increasing source for `SessionChallenge::challenge_sequence`.
///
/// Hold one per desktop identity for the lifetime of the process. It is
/// deliberately not serializable: the durable half of the guarantee is the
/// high-water mark the caller already persists with the accepted session, which
/// is passed back in through [`DesktopChallengeSequence::next`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DesktopChallengeSequence {
    last_issued: u64,
}

impl DesktopChallengeSequence {
    pub const fn new() -> Self {
        Self { last_issued: 0 }
    }

    /// Resumes above a known high-water mark, for example one restored from
    /// durable state at unlock time.
    pub const fn resuming_from(high_water: u64) -> Self {
        Self {
            last_issued: high_water,
        }
    }

    /// The last value handed out, or the highest mark observed, whichever is
    /// greater. Zero means nothing has been issued yet.
    pub const fn last_issued(&self) -> u64 {
        self.last_issued
    }

    /// Raises the counter to a mark observed elsewhere, never lowers it.
    pub const fn observe(&mut self, high_water: u64) {
        if high_water > self.last_issued {
            self.last_issued = high_water;
        }
    }

    /// Issues the next challenge sequence.
    ///
    /// `durable_high_water` is the largest sequence the desktop has durably
    /// recorded as accepted; pass `0` when there is none. `now` is the unix
    /// second the challenge is being issued at, and only raises the floor: a
    /// clock that jumps backwards can never lower the counter.
    ///
    /// The result is always non-zero and always strictly greater than every
    /// value this source has issued or observed, so the peer's replay guard
    /// accepts it in order. Exhaustion is refused rather than wrapped, because
    /// reissuing a consumed sequence is precisely what the guard exists to stop.
    pub fn next(&mut self, durable_high_water: u64, now: u64) -> CompanionResult<u64> {
        self.observe(durable_high_water);
        let clock_floor = now.saturating_mul(SEQUENCES_PER_SECOND);
        let stepped = self
            .last_issued
            .checked_add(1)
            .ok_or(CompanionError::SequenceReplay)?;
        let next = stepped.max(clock_floor);
        self.last_issued = next;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole contract in one assertion: consecutive challenges from the same
    /// desktop must be strictly increasing, because the phone's replay guard
    /// refuses anything that is not.
    #[test]
    fn consecutive_sequences_are_strictly_increasing_within_one_second() {
        let mut source = DesktopChallengeSequence::new();
        let mut previous = 0;
        for _ in 0..1_000 {
            let next = source.next(0, 1_785_803_758).unwrap();
            assert!(next > previous, "{next} did not exceed {previous}");
            assert_ne!(next, 0);
            previous = next;
        }
    }

    #[test]
    fn a_later_second_raises_the_counter_and_an_earlier_second_cannot_lower_it() {
        let mut source = DesktopChallengeSequence::new();
        let first = source.next(0, 1_785_803_758).unwrap();
        let later = source.next(0, 1_785_803_759).unwrap();
        assert!(later > first);
        // A backwards clock step must never reissue a consumed sequence.
        let after_backwards_clock = source.next(0, 1_785_800_000).unwrap();
        assert_eq!(after_backwards_clock, later + 1);
    }

    /// Restart safety without a durable write: a fresh source in a later second
    /// still issues above everything the previous process issued.
    #[test]
    fn a_restarted_source_issues_above_the_previous_process() {
        let mut before = DesktopChallengeSequence::new();
        let last_before_restart = (0..64)
            .map(|_| before.next(0, 1_785_803_758).unwrap())
            .next_back()
            .unwrap();
        let mut after_restart = DesktopChallengeSequence::new();
        assert!(after_restart.next(0, 1_785_803_759).unwrap() > last_before_restart);
    }

    /// A durable mark, wherever it came from, is never reissued.
    #[test]
    fn a_durable_high_water_mark_is_never_reissued() {
        // The mark the live phone actually held for this scope.
        const OBSERVED: u64 = 15_556_705_341_435_925_004;
        let mut source = DesktopChallengeSequence::new();
        assert_eq!(source.next(OBSERVED, 1_785_803_758).unwrap(), OBSERVED + 1);
        assert_eq!(source.next(OBSERVED, 1_785_803_759).unwrap(), OBSERVED + 2);
        assert_eq!(
            DesktopChallengeSequence::resuming_from(OBSERVED)
                .next(0, 1_785_803_758)
                .unwrap(),
            OBSERVED + 1
        );
    }

    #[test]
    fn exhaustion_is_refused_instead_of_wrapping() {
        let mut source = DesktopChallengeSequence::resuming_from(u64::MAX);
        assert_eq!(
            source.next(0, 1_785_803_758),
            Err(CompanionError::SequenceReplay)
        );
        assert_eq!(source.last_issued(), u64::MAX);
    }
}
