// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use core::num::NonZeroU32;
use std::time::{Duration, Instant};

/// Paces packet emission at a fixed interval of `1 / rate`.
///
/// The first packet is admitted immediately. No budget accrues while the sender stalls, so the
/// rate is never exceeded over any window and there are no bursts.
#[derive(Debug)]
pub(super) struct Pacer {
    interval: Duration,
    next_at: Instant,
}

impl Pacer {
    pub(super) fn new(rate: NonZeroU32) -> Self {
        Self {
            // Rates above 1GHz truncate to a zero interval, i.e. effectively unpaced.
            interval: Duration::from_secs(1) / rate.get(),
            next_at: Instant::now(),
        }
    }

    /// Waits until the next send slot, returning `false` without sleeping if the slot cannot be
    /// consumed before `deadline`.
    pub(super) fn pace(&mut self, deadline: Instant) -> bool {
        let now = Instant::now();
        if now >= deadline || self.next_at >= deadline {
            return false;
        }

        if self.next_at > now {
            std::thread::sleep(self.next_at - now);
        }

        // Schedule the next slot relative to the later of the consumed slot and the send time,
        // so time spent stalled does not accumulate into a catch-up burst.
        self.next_at = self.next_at.max(now) + self.interval;

        true
    }
}

/// The outcome of a `Map::send_unknown_path_secrets` call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SendStats {
    /// Packets successfully handed to the socket.
    pub sent: usize,
    /// Entries whose send failed with an I/O error.
    pub failed: usize,
    /// Entries never attempted because the deadline expired first.
    pub remaining: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rate(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    fn far_deadline() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    #[test]
    fn first_send_is_immediate() {
        let mut pacer = Pacer::new(rate(1));

        let start = Instant::now();
        assert!(pacer.pace(far_deadline()));
        assert!(start.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn spaces_subsequent_sends() {
        // 50/s -> 20ms interval
        let mut pacer = Pacer::new(rate(50));

        let start = Instant::now();
        assert!(pacer.pace(far_deadline()));
        assert!(pacer.pace(far_deadline()));
        assert!(start.elapsed() >= Duration::from_millis(15));
    }

    #[test]
    fn fails_fast_when_slot_beyond_deadline() {
        // 1/s: after the immediate first send the next slot is a second away. A deadline before
        // that slot must fail without sleeping the interval out.
        let mut pacer = Pacer::new(rate(1));
        assert!(pacer.pace(far_deadline()));

        let start = Instant::now();
        assert!(!pacer.pace(start + Duration::from_millis(50)));
        assert!(start.elapsed() < Duration::from_millis(40));
    }

    #[test]
    fn expired_deadline_fails_immediately() {
        let mut pacer = Pacer::new(rate(1000));
        assert!(!pacer.pace(Instant::now() - Duration::from_millis(1)));
    }

    #[test]
    fn stall_does_not_accumulate_burst() {
        // 100/s -> 10ms interval. After stalling several intervals, one catch-up send goes out
        // immediately, but the next must wait a full interval again.
        let mut pacer = Pacer::new(rate(100));
        assert!(pacer.pace(far_deadline()));

        std::thread::sleep(Duration::from_millis(50));

        let start = Instant::now();
        assert!(pacer.pace(far_deadline()));
        assert!(pacer.pace(far_deadline()));
        assert!(start.elapsed() >= Duration::from_millis(5));
    }
}
