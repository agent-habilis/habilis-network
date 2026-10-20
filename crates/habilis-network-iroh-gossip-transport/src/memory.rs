//! An in-memory stand-in for the gossip topic: every frame that one member sends
//! reaches every other member, as a gossip broadcast does. For tests and for
//! measurements that need the flood without a network.

use std::sync::{Arc, Mutex};

use bytes::Bytes;

use crate::transport::locked;
use crate::{FrameSink, GossipHandle};

/// The members that share one flood.
#[derive(Debug, Default, Clone)]
pub struct MemoryHub {
    inner: Arc<Mutex<Members>>,
}

#[derive(Debug, Default)]
struct Members {
    members: Vec<GossipHandle>,
    /// Every frame that was sent, in order.
    sent: Vec<Bytes>,
}

impl MemoryHub {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `handle` to the flood and attach a sink to it.
    pub fn join(&self, handle: &GossipHandle) {
        locked(&self.inner).members.push(handle.clone());
        handle.attach(Arc::new(MemorySink {
            hub: self.clone(),
            from: handle.clone(),
        }));
    }

    /// Every frame sent so far.
    #[must_use]
    pub fn sent(&self) -> Vec<Bytes> {
        locked(&self.inner).sent.clone()
    }

    /// Deliver `frame` to every member as if `from` had sent it.
    pub fn flood(&self, from: &GossipHandle, frame: &Bytes) {
        let members: Vec<GossipHandle> = {
            let mut inner = locked(&self.inner);
            inner.sent.push(frame.clone());
            inner.members.clone()
        };
        for member in members
            .iter()
            .filter(|member| member.app_id() != from.app_id())
        {
            // A member that is not the destination drops the frame: that is the flood.
            let _ = member.deliver(frame);
        }
    }
}

#[derive(Debug)]
struct MemorySink {
    hub: MemoryHub,
    from: GossipHandle,
}

impl FrameSink for MemorySink {
    fn try_send(&self, frame: Bytes) -> bool {
        self.hub.flood(&self.from, &frame);
        true
    }
}
