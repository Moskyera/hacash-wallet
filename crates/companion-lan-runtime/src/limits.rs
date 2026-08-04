use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::{LanRuntimeError, LanRuntimeResult};

const MAX_TRACKED_RATE_PEERS: usize = 64;
const RATE_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub(crate) struct AdmissionControl {
    state: Arc<Mutex<AdmissionState>>,
    max_per_peer: usize,
    max_attempts_per_minute: usize,
    max_global_attempts_per_minute: usize,
}

#[derive(Debug, Default)]
struct AdmissionState {
    active: HashMap<IpAddr, usize>,
    attempts: VecDeque<PeerAttempts>,
    global_attempts: VecDeque<Instant>,
}

#[derive(Debug)]
struct PeerAttempts {
    ip: IpAddr,
    seen: VecDeque<Instant>,
}

impl AdmissionControl {
    pub fn new(
        max_per_peer: usize,
        max_attempts_per_minute: usize,
        max_global_attempts_per_minute: usize,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(AdmissionState::default())),
            max_per_peer,
            max_attempts_per_minute,
            max_global_attempts_per_minute,
        }
    }

    pub fn admit(&self, ip: IpAddr, now: Instant) -> LanRuntimeResult<PeerPermit> {
        let mut state = self.state.lock().map_err(|_| LanRuntimeError::Task)?;
        prune(&mut state, now);
        let active = state.active.get(&ip).copied().unwrap_or(0);
        if active >= self.max_per_peer
            || state.global_attempts.len() >= self.max_global_attempts_per_minute
        {
            return Err(LanRuntimeError::Capacity);
        }

        let index = state.attempts.iter().position(|entry| entry.ip == ip);
        if index.is_none() && state.attempts.len() >= MAX_TRACKED_RATE_PEERS {
            // Never evict a live bucket: eviction would reset its rate budget.
            return Err(LanRuntimeError::Capacity);
        }
        let mut attempts = index
            .and_then(|index| state.attempts.remove(index))
            .unwrap_or(PeerAttempts {
                ip,
                seen: VecDeque::new(),
            });
        if attempts.seen.len() >= self.max_attempts_per_minute {
            state.attempts.push_back(attempts);
            return Err(LanRuntimeError::Capacity);
        }
        attempts.seen.push_back(now);
        state.attempts.push_back(attempts);
        state.global_attempts.push_back(now);
        state.active.insert(ip, active + 1);
        Ok(PeerPermit {
            ip,
            state: Arc::clone(&self.state),
        })
    }
}

fn prune(state: &mut AdmissionState, now: Instant) {
    while state
        .global_attempts
        .front()
        .is_some_and(|seen| now.saturating_duration_since(*seen) >= RATE_WINDOW)
    {
        state.global_attempts.pop_front();
    }
    for entry in &mut state.attempts {
        while entry
            .seen
            .front()
            .is_some_and(|seen| now.saturating_duration_since(*seen) >= RATE_WINDOW)
        {
            entry.seen.pop_front();
        }
    }
    state.attempts.retain(|entry| !entry.seen.is_empty());
}

pub(crate) struct PeerPermit {
    ip: IpAddr,
    state: Arc<Mutex<AdmissionState>>,
}

impl Drop for PeerPermit {
    fn drop(&mut self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        match state.active.get_mut(&self.ip) {
            Some(value) if *value > 1 => *value -= 1,
            Some(_) => {
                state.active.remove(&self.ip);
            }
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_peer_and_global_rate_limits_release_without_reset() {
        let limiter = AdmissionControl::new(1, 2, 3);
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let now = Instant::now();
        let first = limiter.admit(ip, now).unwrap();
        assert!(matches!(
            limiter.admit(ip, now),
            Err(LanRuntimeError::Capacity)
        ));
        drop(first);
        let second = limiter.admit(ip, now).unwrap();
        drop(second);
        assert!(matches!(
            limiter.admit(ip, now),
            Err(LanRuntimeError::Capacity)
        ));

        let other: IpAddr = "192.168.1.11".parse().unwrap();
        let permit = limiter.admit(other, now).unwrap();
        drop(permit);
        let third: IpAddr = "192.168.1.12".parse().unwrap();
        assert!(matches!(
            limiter.admit(third, now),
            Err(LanRuntimeError::Capacity)
        ));
    }

    #[test]
    fn sixty_fifth_live_peer_is_rejected_instead_of_eviction_reset() {
        let limiter = AdmissionControl::new(1, 2, 1_000);
        let now = Instant::now();
        for suffix in 1..=MAX_TRACKED_RATE_PEERS {
            let ip: IpAddr = format!("10.0.0.{suffix}").parse().unwrap();
            drop(limiter.admit(ip, now).unwrap());
        }
        let overflow: IpAddr = "10.0.1.1".parse().unwrap();
        assert!(matches!(
            limiter.admit(overflow, now),
            Err(LanRuntimeError::Capacity)
        ));
        let known: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(limiter.admit(known, now).is_ok());
    }
}
