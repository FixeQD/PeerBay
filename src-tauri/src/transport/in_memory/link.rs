use std::collections::VecDeque;

use zeroize::Zeroizing;

use super::{config::InMemoryConfig, errors::InMemoryTransportError};
use crate::transport::{ChannelKind, TransportChannel, TransportKind};

pub(super) struct MemoryLink {
    pub(super) first_device_id: String,
    pub(super) second_device_id: String,
    pub(super) id: String,
    pub(super) kind: ChannelKind,
    pub(super) transport: TransportKind,
    max_queue_bytes: usize,
    first_accepted: bool,
    second_accepted: bool,
    pub(super) closed: bool,
    first_to_second: VecDeque<Zeroizing<Vec<u8>>>,
    second_to_first: VecDeque<Zeroizing<Vec<u8>>>,
    first_queued_bytes: usize,
    second_queued_bytes: usize,
}

impl MemoryLink {
    pub(super) fn new(
        first_device_id: String,
        second_device_id: String,
        id: String,
        kind: ChannelKind,
        transport: TransportKind,
        config: InMemoryConfig,
    ) -> Self {
        Self {
            first_device_id,
            second_device_id,
            id,
            kind,
            transport,
            max_queue_bytes: config.max_queue_bytes,
            first_accepted: true,
            second_accepted: false,
            closed: false,
            first_to_second: VecDeque::new(),
            second_to_first: VecDeque::new(),
            first_queued_bytes: 0,
            second_queued_bytes: 0,
        }
    }

    pub(super) fn has_peer(&self, device_id: &str) -> bool {
        self.first_device_id == device_id || self.second_device_id == device_id
    }

    pub(super) fn remote_for(&self, device_id: &str) -> Option<&str> {
        if self.first_device_id == device_id {
            Some(&self.second_device_id)
        } else if self.second_device_id == device_id {
            Some(&self.first_device_id)
        } else {
            None
        }
    }

    pub(super) fn accepted_by(&self, device_id: &str) -> bool {
        if self.first_device_id == device_id {
            self.first_accepted
        } else if self.second_device_id == device_id {
            self.second_accepted
        } else {
            false
        }
    }

    pub(super) fn mark_accepted(&mut self, device_id: &str) -> eros::Result<()> {
        if self.first_device_id == device_id {
            self.first_accepted = true;
        } else if self.second_device_id == device_id {
            self.second_accepted = true;
        } else {
            return Err(eros::error!(InMemoryTransportError::ChannelNotFound));
        }
        Ok(())
    }

    pub(super) fn channel(&self) -> TransportChannel {
        TransportChannel::new(self.id.clone(), self.transport, self.kind)
            .expect("generated in-memory channel ID must be valid")
    }

    pub(super) fn queued_bytes_from(&self, device_id: &str) -> usize {
        if self.first_device_id == device_id {
            self.first_queued_bytes
        } else {
            self.second_queued_bytes
        }
    }

    pub(super) fn enqueue(
        &mut self,
        device_id: &str,
        payload: Zeroizing<Vec<u8>>,
    ) -> eros::Result<()> {
        if self.queued_bytes_from(device_id) + payload.len() > self.max_queue_bytes {
            return Err(eros::error!(InMemoryTransportError::QueueFull {
                limit: self.max_queue_bytes,
            }));
        }
        if self.first_device_id == device_id {
            self.first_queued_bytes += payload.len();
            self.first_to_second.push_back(payload);
        } else if self.second_device_id == device_id {
            self.second_queued_bytes += payload.len();
            self.second_to_first.push_back(payload);
        } else {
            return Err(eros::error!(InMemoryTransportError::ChannelNotFound));
        }
        Ok(())
    }

    pub(super) fn dequeue(&mut self, device_id: &str) -> eros::Result<Option<Zeroizing<Vec<u8>>>> {
        let (queue, queued_bytes) = if self.first_device_id == device_id {
            (&mut self.second_to_first, &mut self.second_queued_bytes)
        } else if self.second_device_id == device_id {
            (&mut self.first_to_second, &mut self.first_queued_bytes)
        } else {
            return Err(eros::error!(InMemoryTransportError::ChannelNotFound));
        };
        let Some(payload) = queue.pop_front() else {
            return Ok(None);
        };
        *queued_bytes -= payload.len();
        Ok(Some(payload))
    }

    pub(super) fn clear(&mut self) {
        self.first_to_second.clear();
        self.second_to_first.clear();
        self.first_queued_bytes = 0;
        self.second_queued_bytes = 0;
    }
}
