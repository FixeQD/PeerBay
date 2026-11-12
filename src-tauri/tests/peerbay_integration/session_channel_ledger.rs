use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use peerbay_lib::session::{
    ChannelReleaseSummary, MAX_TRACKED_CHANNELS, ReleaseError, SessionChannelLedger,
};
use peerbay_lib::transport::{
    ChannelKind, InMemoryTransport, PeerEndpoint, Transport, TransportChannel, TransportKind,
    TransportMetrics,
};

fn endpoint(id: &str) -> PeerEndpoint {
    PeerEndpoint::new(id, "127.0.0.1:9", TransportKind::Loopback)
        .expect("fixture peer endpoint is valid")
}

fn in_memory_pair() -> (Arc<InMemoryTransport>, Arc<InMemoryTransport>) {
    let (a, b) = InMemoryTransport::pair(
        endpoint("00000000-0000-0000-0000-000000000001"),
        endpoint("00000000-0000-0000-0000-000000000002"),
    )
    .expect("fixture transport pair");
    (Arc::new(a), Arc::new(b))
}

#[derive(Debug)]
enum FixtureError {
    ForcedCloseFailure,
}

impl std::fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForcedCloseFailure => write!(formatter, "forced close failure"),
        }
    }
}

impl std::error::Error for FixtureError {}

struct FailingCloseTransport {
    inner: Arc<InMemoryTransport>,
    fail_ids: Mutex<HashSet<String>>,
}

impl Transport for FailingCloseTransport {
    fn kind(&self) -> TransportKind {
        self.inner.kind()
    }

    fn discover(&self) -> eros::Result<Vec<PeerEndpoint>> {
        self.inner.discover()
    }

    fn open(&self, peer: &PeerEndpoint, channel: ChannelKind) -> eros::Result<TransportChannel> {
        self.inner.open(peer, channel)
    }

    fn close(&self, channel: &TransportChannel) -> eros::Result<()> {
        if self
            .fail_ids
            .lock()
            .expect("fixture mutex")
            .contains(channel.id())
        {
            return Err(eros::error!(FixtureError::ForcedCloseFailure));
        }
        self.inner.close(channel)
    }

    fn metrics(&self, channel: &TransportChannel) -> eros::Result<TransportMetrics> {
        self.inner.metrics(channel)
    }

    fn supports(&self, channel: ChannelKind) -> bool {
        self.inner.supports(channel)
    }

    fn migrate(
        &self,
        channel: &TransportChannel,
        target: TransportKind,
    ) -> eros::Result<TransportChannel> {
        self.inner.migrate(channel, target)
    }
}

fn tracked_trio(
    a: &Arc<InMemoryTransport>,
    peer: &PeerEndpoint,
) -> (SessionChannelLedger, Vec<TransportChannel>) {
    let mut ledger = SessionChannelLedger::new();
    let mut channels = Vec::new();
    for _ in 0..3 {
        let channel = a.open(peer, ChannelKind::Control).expect("channel opens");
        ledger
            .track(a.clone(), channel.clone())
            .expect("fixture track");
        channels.push(channel);
    }
    (ledger, channels)
}

#[test]
fn close_all_closes_every_tracked_channel() {
    let (a, _b) = in_memory_pair();
    let peer = endpoint("00000000-0000-0000-0000-000000000002");
    let (mut ledger, channels) = tracked_trio(&a, &peer);
    assert_eq!(ledger.tracked_channels(), 3);
    assert_eq!(ledger.open_channels(), 3);

    let summary = ledger.close_all();

    assert_eq!(
        summary,
        ChannelReleaseSummary {
            closed: 3,
            failed: 0,
            already_closed: 0
        }
    );
    for channel in &channels {
        assert!(
            !a.is_open(channel).expect("channel metadata"),
            "every tracked channel must be closed by close_all"
        );
    }
    assert_eq!(ledger.open_channels(), 0);
    assert!(!ledger.is_empty(), "entries are kept until drain");
}

#[test]
fn close_all_is_best_effort_and_retryable() {
    let (a, _b) = in_memory_pair();
    let peer = endpoint("00000000-0000-0000-0000-000000000002");
    let wrapper = Arc::new(FailingCloseTransport {
        inner: a.clone(),
        fail_ids: Mutex::new(HashSet::new()),
    });

    let mut ledger = SessionChannelLedger::new();
    let mut channels = Vec::new();
    for _ in 0..3 {
        let channel = a.open(&peer, ChannelKind::Control).expect("channel opens");
        ledger
            .track(wrapper.clone(), channel.clone())
            .expect("fixture track");
        channels.push(channel);
    }
    wrapper
        .fail_ids
        .lock()
        .expect("fixture mutex")
        .insert(channels[1].id().to_owned());

    let summary = ledger.close_all();

    assert_eq!(
        summary,
        ChannelReleaseSummary {
            closed: 2,
            failed: 1,
            already_closed: 0
        },
        "one close failure must not abort the remaining closes"
    );
    assert!(
        a.is_open(&channels[1]).expect("channel metadata"),
        "a failed close keeps its entry open for a retry"
    );

    let summary = ledger.close_all();

    assert_eq!(
        summary,
        ChannelReleaseSummary {
            closed: 0,
            failed: 1,
            already_closed: 2
        },
        "the retry only attempts the entry that is still open"
    );
    assert_eq!(ledger.open_channels(), 1);
}

#[test]
fn track_enforces_capacity() {
    let (a, _b) = in_memory_pair();
    let peer = endpoint("00000000-0000-0000-0000-000000000002");
    let mut ledger = SessionChannelLedger::new();
    for _ in 0..MAX_TRACKED_CHANNELS {
        let channel = a.open(&peer, ChannelKind::Control).expect("channel opens");
        ledger.track(a.clone(), channel).expect("track under cap");
    }

    let extra = a.open(&peer, ChannelKind::Control).expect("channel opens");
    let error = ledger
        .track(a.clone(), extra)
        .expect_err("the cap must refuse further tracking");

    assert!(
        matches!(
            error.downcast_inner::<ReleaseError>(),
            Ok(ReleaseError::LedgerFull {
                tracked,
                max
            }) if tracked == MAX_TRACKED_CHANNELS && max == MAX_TRACKED_CHANNELS
        ),
        "track must fail with LedgerFull at the cap"
    );
    assert_eq!(ledger.tracked_channels(), MAX_TRACKED_CHANNELS);
}

#[test]
fn close_channel_is_idempotent_and_validated() {
    let (a, _b) = in_memory_pair();
    let peer = endpoint("00000000-0000-0000-0000-000000000002");
    let channel = a.open(&peer, ChannelKind::Control).expect("channel opens");
    let mut ledger = SessionChannelLedger::new();
    ledger
        .track(a.clone(), channel.clone())
        .expect("fixture track");

    let error = ledger
        .close_channel("memory-channel-9999")
        .expect_err("an untracked id must be refused");
    assert!(
        matches!(
            error.downcast_inner::<ReleaseError>(),
            Ok(ReleaseError::UnknownChannel { id }) if id == "memory-channel-9999"
        ),
        "close_channel must fail with UnknownChannel for untracked ids"
    );

    assert!(
        ledger.close_channel(channel.id()).expect("close tracked"),
        "the first close reports that it closed the channel"
    );
    assert!(
        !a.is_open(&channel).expect("channel metadata"),
        "the transport channel is closed"
    );
    assert!(
        !ledger.close_channel(channel.id()).expect("repeat close"),
        "a repeated close reports the entry was already closed"
    );
    assert_eq!(ledger.open_channels(), 0);
}

#[test]
fn drain_removes_only_closed_entries() {
    let (a, _b) = in_memory_pair();
    let peer = endpoint("00000000-0000-0000-0000-000000000002");
    let (mut ledger, channels) = tracked_trio(&a, &peer);
    ledger
        .close_channel(channels[1].id())
        .expect("close the middle channel");

    ledger.drain();

    assert_eq!(ledger.tracked_channels(), 2, "drain keeps the open entries");
    assert_eq!(ledger.open_channels(), 2);
    assert!(
        !a.is_open(&channels[1]).expect("channel metadata"),
        "the drained entry stays closed on the transport"
    );

    ledger.close_all();
    assert!(
        !a.is_open(&channels[0]).expect("channel metadata"),
        "kept entries remain closeable through the ledger"
    );
    assert!(
        !a.is_open(&channels[2]).expect("channel metadata"),
        "kept entries remain closeable through the ledger"
    );

    ledger.drain();
    assert!(
        ledger.is_empty(),
        "drain after closing everything empties the ledger"
    );
}
