// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    event::{testing, tracing},
    path::secret::{schedule, sender},
};
use core::num::NonZeroU32;
use s2n_quic_core::{dc, time::NoopClock as Clock};
use std::{
    collections::HashSet,
    fmt,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Instant,
};

fn fake_entry(port: u16) -> Arc<Entry> {
    Entry::fake((Ipv4Addr::LOCALHOST, port).into(), None)
}

#[test]
fn cleans_after_delay() {
    let signer = stateless_reset::Signer::new(b"secret");
    let map = State::builder()
        .with_signer(signer)
        .with_capacity(50)
        .with_clock(Clock)
        .with_subscriber(tracing::Subscriber::default())
        .build()
        .unwrap();

    // Stop background processing. We expect to manually invoke clean, and a background worker
    // might interfere with our state.
    map.cleaner.stop();

    let first = fake_entry(1);
    let second = fake_entry(1);
    let third = fake_entry(1);
    map.test_insert(first.clone());
    map.test_insert(second.clone());

    assert!(map.ids.contains_key(first.id()));
    assert!(map.ids.contains_key(second.id()));

    map.cleaner.clean(&map, 1);
    map.cleaner.clean(&map, 1);

    map.test_insert(third.clone());

    assert!(!map.ids.contains_key(first.id()));
    assert!(map.ids.contains_key(second.id()));
    assert!(map.ids.contains_key(third.id()));
}

#[test]
fn thread_shutdown() {
    let signer = stateless_reset::Signer::new(b"secret");
    let map = State::builder()
        .with_signer(signer)
        .with_capacity(10)
        .with_clock(Clock)
        .with_subscriber((
            tracing::Subscriber::default(),
            testing::Subscriber::snapshot(),
        ))
        .build()
        .unwrap();
    let state = Arc::downgrade(&map);
    drop(map);

    let iterations = 10;
    let max_time = core::time::Duration::from_secs(2);

    for _ in 0..iterations {
        // Nothing is holding on to the state, so the thread should shutdown (mpsc disconnects or on
        // next loop around if that fails for some reason).
        if state.strong_count() == 0 {
            return;
        }
        std::thread::sleep(max_time / iterations);
    }

    panic!("thread did not shut down after {max_time:?}");
}

#[test]
fn serialize_to_disk_writes_configured_entries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets");

    let signer = stateless_reset::Signer::new(b"secret");
    let map = State::builder()
        .with_signer(signer)
        .with_capacity(50)
        .with_clock(Clock)
        .with_subscriber(tracing::Subscriber::default())
        .with_serializer(disk::Serializer::builder(&path).build().unwrap())
        .build()
        .unwrap();

    // Stop background processing so the cleaner thread doesn't race our manual serialization.
    map.cleaner.stop();

    let first = fake_entry(1);
    let second = fake_entry(2);
    map.test_insert(first.clone());
    map.test_insert(second.clone());

    map.serialize_to_disk().unwrap();

    let mut decoded: Vec<disk::DiskEntry> = disk::deserialize(&path)
        .unwrap()
        .map(|e| e.unwrap())
        .collect();
    decoded.sort_by_key(|e| e.peer);

    let mut expected = vec![
        disk::DiskEntry {
            peer: *first.peer(),
            id: *first.id(),
        },
        disk::DiskEntry {
            peer: *second.peer(),
            id: *second.id(),
        },
    ];
    expected.sort_by_key(|e| e.peer);

    assert_eq!(decoded, expected);
}

#[test]
fn serialize_to_disk_emits_event() {
    use std::sync::atomic::Ordering;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets");

    let subscriber = Arc::new(testing::Subscriber::no_snapshot());

    let signer = stateless_reset::Signer::new(b"secret");
    let map = State::builder()
        .with_signer(signer)
        .with_capacity(50)
        .with_clock(Clock)
        .with_subscriber(subscriber.clone())
        .with_serializer(disk::Serializer::builder(&path).build().unwrap())
        .build()
        .unwrap();

    // Stop background processing so the cleaner thread doesn't race our manual serialization.
    map.cleaner.stop();

    map.test_insert(fake_entry(1));
    map.test_insert(fake_entry(2));

    map.serialize_to_disk().unwrap();

    assert_eq!(
        subscriber
            .path_secret_map_serialized
            .load(Ordering::Relaxed),
        1
    );
}

#[test]
fn serialize_to_disk_without_serializer_is_noop() {
    let signer = stateless_reset::Signer::new(b"secret");
    let map = State::builder()
        .with_signer(signer)
        .with_capacity(50)
        .with_clock(Clock)
        .with_subscriber(tracing::Subscriber::default())
        .build()
        .unwrap();
    map.cleaner.stop();

    // No serializer configured: this is a no-op and must not error.
    map.serialize_to_disk().unwrap();
}

/// Builds a map with background processing stopped.
fn emission_test_map(signer_secret: &[u8]) -> Arc<State<Clock, tracing::Subscriber>> {
    let map = State::builder()
        .with_signer(stateless_reset::Signer::new(signer_secret))
        .with_capacity(50)
        .with_clock(Clock)
        .with_subscriber(tracing::Subscriber::default())
        .build()
        .unwrap();
    map.cleaner.stop();
    map
}

#[test]
fn send_unknown_path_secrets_emits_authentic_packets() {
    let receiver = std::net::UdpSocket::bind("[::1]:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let peer = receiver.local_addr().unwrap();

    let map = emission_test_map(b"emit-secret");

    let ids = [TestId(1).id(), TestId(2).id()];
    let mut entries = ids.iter().map(|id| disk::DiskEntry { peer, id: *id });

    let rate = NonZeroU32::new(1000).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let stats = map
        .send_unknown_path_secrets(&mut entries, rate, deadline)
        .unwrap();

    assert_eq!(stats.sent, 2);
    assert_eq!(stats.failed, 0);
    assert_eq!(stats.remaining, 0);

    let verifier = stateless_reset::Signer::new(b"emit-secret");
    let wrong_key = stateless_reset::Signer::new(b"wrong-secret");

    let mut seen = HashSet::new();
    for _ in 0..ids.len() {
        let mut buffer = [0u8; 64];
        let (len, _from) = receiver.recv_from(&mut buffer).unwrap();

        let decoder = s2n_codec::DecoderBufferMut::new(&mut buffer[..len]);
        let (packet, _) = control::Packet::decode(decoder).unwrap();
        let control::Packet::UnknownPathSecret(packet) = packet else {
            panic!("expected an UnknownPathSecret packet, got {packet:?}");
        };

        let id = *packet.credential_id();
        assert!(ids.contains(&id), "unexpected credential id {id}");
        assert!(packet.authenticate(&verifier.sign(&id)).is_some());
        assert!(packet.authenticate(&wrong_key.sign(&id)).is_none());
        seen.insert(id);
    }
    assert_eq!(seen.len(), ids.len());
}

#[test]
fn send_unknown_path_secrets_expired_deadline_sends_nothing() {
    let map = emission_test_map(b"emit-secret");

    let peer: SocketAddr = "[::1]:4433".parse().unwrap();
    let mut entries = (1..=3).map(|i| disk::DiskEntry {
        peer,
        id: TestId(i).id(),
    });

    let rate = NonZeroU32::new(1000).unwrap();
    let deadline = Instant::now() - Duration::from_millis(1);
    let stats = map
        .send_unknown_path_secrets(&mut entries, rate, deadline)
        .unwrap();

    assert_eq!(stats.sent, 0);
    assert_eq!(stats.failed, 0);
    assert_eq!(stats.remaining, 3);
}

#[test]
fn send_unknown_path_secrets_deadline_bounds_paced_sends() {
    let receiver = std::net::UdpSocket::bind("[::1]:0").unwrap();
    let peer = receiver.local_addr().unwrap();

    let map = emission_test_map(b"emit-secret");

    const TOTAL: u8 = 5;
    let mut entries = (1..=TOTAL).map(|i| disk::DiskEntry {
        peer,
        id: TestId(i).id(),
    });

    // 10 packets/s: the first send is immediate, then one per 100ms. A 250ms deadline admits
    // only the first few slots, so the run must be cut short. Exact counts are
    // timing-sensitive, so assert the invariants rather than a precise split.
    let rate = NonZeroU32::new(10).unwrap();
    let start = Instant::now();
    let deadline = start + Duration::from_millis(250);
    let stats = map
        .send_unknown_path_secrets(&mut entries, rate, deadline)
        .unwrap();

    assert!(stats.sent >= 1, "the first send is unpaced");
    assert!(
        stats.sent < usize::from(TOTAL),
        "the deadline must cut the run short"
    );
    assert_eq!(stats.failed, 0);
    assert_eq!(stats.sent + stats.remaining, usize::from(TOTAL));
    // n sends require at least (n - 1) full pacing intervals to have elapsed.
    assert!(start.elapsed() >= Duration::from_millis(100) * (stats.sent as u32 - 1));
}

#[derive(Debug, Default)]
struct Model {
    invariants: HashSet<Invariant>,
}

#[derive(bolero::TypeGenerator, Debug, Copy, Clone)]
enum Operation {
    Insert { ip: u8, path_secret_id: TestId },
    AdvanceTime,
    ReceiveUnknown { path_secret_id: TestId },
}

#[derive(bolero::TypeGenerator, PartialEq, Eq, Hash, Copy, Clone)]
struct TestId(u8);

impl fmt::Debug for TestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TestId")
            .field(&self.0)
            .field(&self.id())
            .finish()
    }
}

impl TestId {
    fn secret(self) -> schedule::Secret {
        let mut export_secret = [0; 32];
        export_secret[0] = self.0;
        schedule::Secret::new(
            schedule::Ciphersuite::AES_GCM_128_SHA256,
            dc::SUPPORTED_VERSIONS[0],
            s2n_quic_core::endpoint::Type::Client,
            &export_secret,
        )
    }

    fn id(self) -> Id {
        *self.secret().id()
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
enum Invariant {
    ContainsIp(SocketAddr),
    ContainsId(Id),
    IdRemoved(Id),
}

impl Model {
    fn perform(&mut self, operation: Operation, state: &State<Clock, tracing::Subscriber>) {
        match operation {
            Operation::Insert { ip, path_secret_id } => {
                let ip = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from([0, 0, 0, ip]), 0));
                let secret = path_secret_id.secret();
                let id = *secret.id();

                let stateless_reset = state.signer().sign(&id);
                state.test_insert(Arc::new(Entry::new(
                    ip,
                    secret,
                    sender::State::new(stateless_reset),
                    receiver::State::new(),
                    dc::testing::TEST_APPLICATION_PARAMS,
                    dc::testing::TEST_REHANDSHAKE_PERIOD,
                    None,
                )));

                self.invariants.insert(Invariant::ContainsIp(ip));
                self.invariants.insert(Invariant::ContainsId(id));
            }
            Operation::AdvanceTime => {
                let mut invalidated = Vec::new();
                self.invariants.retain(|invariant| {
                    if let Invariant::ContainsId(id) = invariant {
                        if state
                            .get_by_id_untracked(id)
                            .is_none_or(|v| v.retired_at().is_some())
                        {
                            invalidated.push(*id);
                            return false;
                        }
                    }

                    true
                });
                for id in invalidated {
                    assert!(self.invariants.insert(Invariant::IdRemoved(id)), "{id:?}");
                }

                // Evict all stale records *now*.
                state.cleaner.clean(state, 0);
            }
            Operation::ReceiveUnknown { path_secret_id } => {
                let id = path_secret_id.id();
                // This is signing with the "wrong" signer, but currently all of the signers used
                // in this test are keyed the same way so it doesn't matter.
                let stateless_reset = state.signer.sign(&id);
                let packet =
                    crate::packet::secret_control::unknown_path_secret::Packet::new_for_test(
                        id,
                        &stateless_reset,
                    );

                state
                    .handle_unknown_path_secret_packet(&packet, &"127.0.0.1:1234".parse().unwrap());

                if state.should_evict_on_unknown_path_secret()
                    && self.invariants.contains(&Invariant::ContainsId(id))
                {
                    self.invariants.retain(|invariant| {
                        if let Invariant::ContainsId(prev_id) = invariant {
                            if prev_id == &id {
                                return false;
                            }
                        }

                        true
                    });

                    self.invariants.insert(Invariant::IdRemoved(id));
                }
            }
        }
    }

    fn check_invariants(&self, state: &State<Clock, tracing::Subscriber>) {
        for invariant in self.invariants.iter() {
            // We avoid assertions for contains() if we're running the small capacity test, since
            // they are likely broken -- we semi-randomly evict peers in that case.
            match invariant {
                Invariant::ContainsIp(ip) => {
                    if state.max_capacity != 5 {
                        assert!(state.peers.contains_key(ip), "{ip:?}");
                    }
                }
                Invariant::ContainsId(id) => {
                    if state.max_capacity != 5 {
                        assert!(state.ids.contains_key(id), "{id:?}");
                    }
                }
                Invariant::IdRemoved(id) => {
                    assert!(!state.ids.contains_key(id), "{:?}", state.ids.get(*id));
                }
            }
        }

        // All entries in the peer set should also be in the `ids` set (which is actively garbage
        // collected).
        // FIXME: this requires a clean() call which may have not happened yet.
        // state.peers.iter(|_, entry| {
        //     assert!(
        //         state.ids.contains_key(entry.secret.id()),
        //         "{:?} not present in IDs",
        //         entry.secret.id()
        //     );
        // });
    }
}

fn has_duplicate_pids(ops: &[Operation]) -> bool {
    let mut ids = HashSet::new();
    for op in ops.iter() {
        match op {
            Operation::Insert {
                ip: _,
                path_secret_id,
            } => {
                if !ids.insert(path_secret_id) {
                    return true;
                }
            }
            Operation::AdvanceTime => {}
            Operation::ReceiveUnknown { path_secret_id: _ } => {
                // no-op, we're fine receiving unknown pids.
            }
        }
    }

    false
}

fn check_invariants_inner(should_evict_on_unknown_path_secret: bool) {
    bolero::check!()
        .with_type::<Vec<Operation>>()
        .with_iterations(10_000)
        .for_each(|input: &Vec<Operation>| {
            if has_duplicate_pids(input) {
                // Ignore this attempt.
                return;
            }

            let mut model = Model::default();
            let signer = stateless_reset::Signer::new(b"secret");
            let mut map = State::builder()
                .with_signer(signer)
                .with_capacity(10_000)
                .with_evict_on_unknown_path_secret(should_evict_on_unknown_path_secret)
                .with_clock(Clock)
                .with_subscriber(tracing::Subscriber::default())
                .build()
                .unwrap();

            // Avoid background work interfering with testing.
            map.cleaner.stop();

            Arc::<State<Clock, tracing::Subscriber>>::get_mut(&mut map)
                .unwrap()
                .set_max_capacity(5);

            model.check_invariants(&map);

            for op in input {
                model.perform(*op, &map);
                model.check_invariants(&map);
            }
        })
}

#[test]
fn check_invariants() {
    check_invariants_inner(false);
}

#[test]
fn check_invariants_evict_unknown_pid() {
    check_invariants_inner(true);
}

#[test]
#[ignore = "fixed size maps currently break overflow assumptions, too small bucket size"]
fn check_invariants_no_overflow() {
    bolero::check!()
        .with_type::<Vec<Operation>>()
        .with_iterations(10_000)
        .for_each(|input: &Vec<Operation>| {
            if has_duplicate_pids(input) {
                // Ignore this attempt.
                return;
            }

            let mut model = Model::default();
            let signer = stateless_reset::Signer::new(b"secret");
            let map = State::builder()
                .with_signer(signer)
                .with_capacity(10_000)
                .with_clock(Clock)
                .with_subscriber(tracing::Subscriber::default())
                .build()
                .unwrap();

            // Avoid background work interfering with testing.
            map.cleaner.stop();

            model.check_invariants(&map);

            for op in input {
                model.perform(*op, &map);
                model.check_invariants(&map);
            }
        })
}

// Unfortunately actually checking memory usage is probably too flaky, but if this did end up
// growing at all on a per-entry basis we'd quickly overflow available memory (this is 153GB of
// peer entries at minimum).
//
// For now ignored but run locally to confirm this works.
#[test]
#[ignore = "memory growth takes a long time to run"]
fn no_memory_growth() {
    let signer = stateless_reset::Signer::new(b"secret");
    let map = State::builder()
        .with_signer(signer)
        .with_capacity(100_000)
        .with_clock(Clock)
        .with_subscriber(tracing::Subscriber::default())
        .build()
        .unwrap();
    map.cleaner.stop();

    for idx in 0..500_000 {
        // FIXME: this ends up 2**16 peers in the `peers` map
        map.test_insert(fake_entry(idx as u16));
    }
}

#[test]
fn unknown_path_secret_evicts() {
    let signer = stateless_reset::Signer::new(b"secret");
    let map = State::builder()
        .with_signer(signer)
        .with_capacity(5)
        .with_evict_on_unknown_path_secret(true)
        .with_clock(Clock)
        .with_subscriber(tracing::Subscriber::default())
        .build()
        .unwrap();

    let entry = fake_entry(0);
    map.test_insert(entry.clone());

    let packet = crate::packet::secret_control::unknown_path_secret::Packet::new_for_test(
        *entry.clone().id(),
        &entry.sender().stateless_reset,
    );

    assert!(map.ids.contains_key(entry.id()), "{:?}", map.ids);
    assert!(map.peers.contains_key(entry.peer()), "{:?}", map.peers);

    map.handle_unknown_path_secret_packet(&packet, &"127.0.0.1:1234".parse().unwrap());

    assert!(!map.ids.contains_key(entry.id()), "{:?}", map.ids);
    assert!(!map.peers.contains_key(entry.peer()), "{:?}", map.peers);
}
