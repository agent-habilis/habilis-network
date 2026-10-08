//! The split of the mesh topic, before anything reads a message (Phase 6, step 5).
//!
//! The mesh topic carries two kinds of message: the signed mesh messages that the event loop
//! handles, and the frames of the gossip transport (first byte `FRAME_KIND`). One task owns the
//! topic receiver and reads it all the time. A frame goes to the transport handle and never
//! further: it does not reach `Message::parse`, `note_inbound`, `mark_seen`, the log, the digests
//! or anti-entropy. Everything else goes to the event loop on a queue that does not drop, so that
//! the work of the loop cannot make the topic lag.

use futures_util::{Stream, StreamExt as _};
use habilis_network_iroh_gossip_transport::GossipHandle;
use habilis_network_iroh_gossip_transport::frame::FRAME_KIND;
use iroh::EndpointId;
use iroh_gossip::api::{ApiError, Event, GossipTopic, JoinOptions};
use iroh_gossip::net::Gossip;
use iroh_gossip::proto::TopicId;
use tokio::sync::{mpsc, oneshot};

use crate::util::tuning::MESH_TOPIC_EVENTS_CAP;

/// Join the mesh topic with a queue that outlasts a stall of the splitter.
pub(crate) async fn subscribe_mesh(
    gossip: &Gossip,
    topic_id: TopicId,
    bootstrap: impl IntoIterator<Item = EndpointId>,
) -> Result<GossipTopic, ApiError> {
    gossip
        .subscribe_with_opts(
            topic_id,
            JoinOptions {
                bootstrap: bootstrap.into_iter().collect(),
                subscription_capacity: MESH_TOPIC_EVENTS_CAP,
            },
        )
        .await
}

/// What the topic yields: the item of `GossipReceiver::next()`.
pub(crate) type TopicItem = Result<Event, ApiError>;

/// The queue of the mesh messages, from the splitter to the event loop. It is bounded by the
/// capacity of the topic subscription: a hostile member must not be able to grow it without
/// limit. When it is full the newest message is dropped and counted, and anti-entropy repairs it
/// (the topic itself does the same when it lags).
type DataRx = mpsc::Receiver<TopicItem>;

/// The queue of the control events (a neighbor up or down, a lag, an error): their volume is
/// bounded by the topology, and none may be dropped.
type ControlRx = mpsc::UnboundedReceiver<TopicItem>;

/// What the splitter does with an item of the topic.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Route {
    /// A frame of the gossip transport: it goes to the handle and no further.
    Frame,
    /// A mesh message, for the data queue.
    Data,
    /// A neighbor event, a lag or an error, for the control queue.
    Control,
}

/// The mesh events that the splitter forwards, with the same `next()` as the topic receiver.
#[derive(Debug)]
pub(crate) struct MeshReceiver<S> {
    data: DataRx,
    control: Option<ControlRx>,
    dead: Option<oneshot::Receiver<S>>,
}

impl<S> MeshReceiver<S> {
    /// The next mesh event, or `None` when the topic ended and the queued messages are read.
    /// The control events come first, so a control event can overtake a mesh message that was
    /// queued before it: nobody relies on the order across the two queues. The end of the topic
    /// comes after the data queued before it.
    pub(crate) async fn next(&mut self) -> Option<TopicItem> {
        loop {
            let Some(control) = self.control.as_mut() else {
                return self.data.recv().await;
            };
            tokio::select! {
                biased;
                item = control.recv() => match item {
                    Some(item) => return Some(item),
                    None => self.control = None,
                },
                item = self.data.recv() => return item,
            }
        }
    }

    /// The topic receiver of a subscription that ended, for the drain of what it buffered. It does
    /// not wait: the task hands the receiver back before it closes the queues, so a loop that has
    /// read the end of the topic finds it here. A subscription that has not ended yields none.
    pub(crate) fn into_dead(mut self) -> Option<S> {
        self.dead.take()?.try_recv().ok()
    }
}

/// Whether a message of the topic is a frame of the gossip transport.
pub(crate) fn is_frame(content: &[u8]) -> bool {
    content.first() == Some(&FRAME_KIND)
}

/// Where an item of the topic goes, with two side effects: a frame is handed to the transport
/// here, and a lag is counted on it. Without a handle (the engine installs one at step 10) a frame is dropped.
pub(crate) fn route_and_deliver(item: &TopicItem, handle: Option<&GossipHandle>) -> Route {
    match item {
        Ok(Event::Received(message)) if is_frame(&message.content) => {
            if let Some(handle) = handle {
                let _ = handle.deliver(&message.content);
            }
            Route::Frame
        }
        Ok(Event::Received(_)) => Route::Data,
        Ok(Event::Lagged) => {
            if let Some(handle) = handle {
                handle.note_lagged();
            }
            Route::Control
        }
        _ => Route::Control,
    }
}

/// Start the task that reads `stream`. `handle` is the gossip transport, if the engine has one.
pub(crate) fn spawn_split<S>(stream: S, handle: Option<GossipHandle>) -> MeshReceiver<S>
where
    S: Stream<Item = TopicItem> + Unpin + Send + 'static,
{
    let (data_tx, data) = mpsc::channel(MESH_TOPIC_EVENTS_CAP);
    let (control_tx, control) = mpsc::unbounded_channel();
    let (dead_tx, dead) = oneshot::channel();
    n0_future::task::spawn(async move {
        let mut stream = stream;
        let mut dropped = 0u64;
        while let Some(item) = stream.next().await {
            let delivered = match route_and_deliver(&item, handle.as_ref()) {
                Route::Frame => true,
                Route::Control => control_tx.send(item).is_ok(),
                Route::Data => match data_tx.try_send(item) {
                    Ok(()) => true,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        dropped += 1;
                        if let Some(handle) = &handle {
                            handle.note_forward_dropped();
                        }
                        // The first drop and then every 256th: a storm must not flood the log.
                        if dropped == 1 || dropped.is_multiple_of(256) {
                            tracing::warn!(
                                target: "habilis_network::gossip",
                                dropped,
                                "mesh message dropped: the queue to the event loop is full"
                            );
                        }
                        true
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => false,
                },
            };
            if !delivered {
                break;
            }
        }
        let _ = dead_tx.send(stream);
    });
    MeshReceiver {
        data,
        control: Some(control),
        dead: Some(dead),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use futures_util::StreamExt as _;
    use futures_util::stream::{self, BoxStream};
    use habilis_network_iroh_gossip_transport::GossipHandle;
    use habilis_network_iroh_gossip_transport::frame;
    use iroh_gossip::api::{Event, Message};
    use iroh_gossip::proto::DeliveryScope;

    use super::{MeshReceiver, TopicItem, spawn_split};
    use crate::testing::endpoint_id;

    type Mesh = MeshReceiver<BoxStream<'static, TopicItem>>;

    /// A topic that the test feeds by hand.
    fn topic() -> (
        tokio::sync::mpsc::UnboundedSender<TopicItem>,
        BoxStream<'static, TopicItem>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let events = stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        })
        .boxed();
        (tx, events)
    }

    fn message(content: Bytes) -> Event {
        Event::Received(Message {
            content,
            scope: DeliveryScope::Neighbors,
            delivered_from: endpoint_id(9),
        })
    }

    /// A frame for the node `app`, as the transport of another member puts it on the topic.
    fn frame_for(app: iroh::EndpointId) -> Bytes {
        frame::encode(app, endpoint_id(8), b"datagram").expect("a frame")
    }

    /// Wait until the handle has counted `frames` frames, or fail after 5 s.
    async fn frames_in(handle: &GossipHandle, frames: u64) {
        for _ in 0..500 {
            if handle.stats().frames_in >= frames {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("only {} of {frames} frames read", handle.stats().frames_in);
    }

    /// A mesh message: its first byte is not the frame kind.
    fn numbered(index: usize) -> Bytes {
        let mut content = b"m".to_vec();
        content.extend_from_slice(&index.to_le_bytes());
        Bytes::from(content)
    }

    async fn next_within(mesh: &mut Mesh) -> Option<TopicItem> {
        tokio::time::timeout(Duration::from_secs(2), mesh.next())
            .await
            .expect("an event within 2 s")
    }

    /// A frame goes to the handle and no further. A mesh message goes to the loop and not to the
    /// handle: the seen set, the log and the digests never see a frame, because `ingest` is not
    /// called for it.
    #[tokio::test]
    async fn a_frame_goes_to_the_handle_and_a_mesh_message_to_the_loop() {
        let handle = GossipHandle::new(endpoint_id(1));
        let (tx, events) = topic();
        let mut mesh = spawn_split(events, Some(handle.clone()));

        tx.send(Ok(message(frame_for(endpoint_id(1)))))
            .expect("send");
        tx.send(Ok(message(Bytes::from_static(b"a mesh message"))))
            .expect("send");

        let Some(Ok(Event::Received(forwarded))) = next_within(&mut mesh).await else {
            panic!("the mesh message must reach the loop");
        };
        assert_eq!(
            forwarded.content,
            Bytes::from_static(b"a mesh message"),
            "the first event of the loop is the mesh message: the frame was not forwarded"
        );
        assert_eq!(handle.stats().queued, 1, "the frame reached the transport");
        assert_eq!(handle.stats().frames_in, 1, "and it was the only one");
    }

    /// `Lagged` raises `topic_lagged` and is still forwarded, so that the loop logs it.
    #[tokio::test]
    async fn a_lagged_event_raises_topic_lagged_and_is_forwarded() {
        let handle = GossipHandle::new(endpoint_id(1));
        let (tx, events) = topic();
        let mut mesh = spawn_split(events, Some(handle.clone()));

        tx.send(Ok(Event::Lagged)).expect("send");

        assert!(
            matches!(next_within(&mut mesh).await, Some(Ok(Event::Lagged))),
            "the loop sees the lag"
        );
        assert_eq!(handle.stats().topic_lagged, 1, "and the handle counted it");
    }

    /// The end of the topic reaches the loop as `None`, and the receiver is handed back for the
    /// drain of what it buffered.
    #[tokio::test]
    async fn the_end_of_the_topic_is_forwarded_and_the_receiver_comes_back() {
        let (tx, events) = topic();
        let mut mesh = spawn_split(events, None);

        tx.send(Ok(message(Bytes::from_static(b"last"))))
            .expect("send");
        drop(tx);

        assert!(matches!(
            next_within(&mut mesh).await,
            Some(Ok(Event::Received(_)))
        ));
        assert!(next_within(&mut mesh).await.is_none(), "the topic ended");
        assert!(mesh.into_dead().is_some(), "the dead receiver comes back");
    }

    /// A loop that is busy does not make the topic lag: the splitter reads at once, and the mesh
    /// messages wait in order for the loop.
    #[tokio::test]
    async fn a_busy_loop_does_not_stop_the_splitter_reading() {
        let handle = GossipHandle::new(endpoint_id(1));
        let (tx, events) = topic();
        let mut mesh = spawn_split(events, Some(handle.clone()));

        for index in 0..10u8 {
            tx.send(Ok(message(Bytes::from(vec![b'm', index]))))
                .expect("send");
            for _ in 0..1000 {
                tx.send(Ok(message(frame_for(endpoint_id(1)))))
                    .expect("send");
            }
        }
        // The loop reads nothing; the splitter must read the whole topic meanwhile.
        frames_in(&handle, 10_000).await;
        assert_eq!(
            handle.stats().frames_in,
            10_000,
            "every frame was read while the loop was busy"
        );
        for index in 0..10u8 {
            let Some(Ok(Event::Received(forwarded))) = next_within(&mut mesh).await else {
                panic!("a mesh message was lost");
            };
            assert_eq!(
                forwarded.content,
                Bytes::from(vec![b'm', index]),
                "in order"
            );
        }
    }

    /// A storm of mesh messages beyond the queue: the splitter keeps reading, the frames still
    /// reach the transport, the newest mesh messages are dropped and counted, and the control
    /// events (a `NeighborDown`) are never dropped and come first.
    #[tokio::test]
    async fn a_storm_of_mesh_messages_drops_the_newest_and_keeps_the_frames_and_control_events() {
        use crate::util::tuning::MESH_TOPIC_EVENTS_CAP;

        let handle = GossipHandle::new(endpoint_id(1));
        let (tx, events) = topic();
        let mut mesh = spawn_split(events, Some(handle.clone()));
        let storm = MESH_TOPIC_EVENTS_CAP + 100;

        for index in 0..storm {
            tx.send(Ok(message(numbered(index)))).expect("send");
            tx.send(Ok(message(frame_for(endpoint_id(1)))))
                .expect("send");
        }
        tx.send(Ok(Event::NeighborDown(endpoint_id(7))))
            .expect("send");
        // The loop reads nothing from the mesh meanwhile.
        frames_in(&handle, storm as u64).await;

        let stats = handle.stats();
        assert_eq!(
            stats.frames_in, storm as u64,
            "every frame reached the transport"
        );
        assert_eq!(stats.topic_lagged, 0, "the topic did not lag");
        assert_eq!(
            stats.forward_dropped, 100,
            "the newest 100 mesh messages were dropped"
        );
        assert!(
            matches!(
                next_within(&mut mesh).await,
                Some(Ok(Event::NeighborDown(_)))
            ),
            "the control event comes first and was not dropped"
        );
        let Some(Ok(Event::Received(first))) = next_within(&mut mesh).await else {
            panic!("the oldest mesh message is kept");
        };
        assert_eq!(first.content, numbered(0), "oldest first");
    }

    /// The end of the topic reaches the loop only after the mesh messages that were queued
    /// before it: none is lost behind the control channel.
    #[tokio::test]
    async fn the_end_of_the_topic_comes_after_the_queued_mesh_messages() {
        let (tx, events) = topic();
        let mut mesh = spawn_split(events, None);

        for index in 0..3u8 {
            tx.send(Ok(message(numbered(usize::from(index)))))
                .expect("send");
        }
        drop(tx);
        tokio::time::sleep(Duration::from_millis(100)).await;

        for index in 0..3u8 {
            let Some(Ok(Event::Received(item))) = next_within(&mut mesh).await else {
                panic!("a queued mesh message was lost");
            };
            assert_eq!(item.content, numbered(usize::from(index)));
        }
        assert!(next_within(&mut mesh).await.is_none(), "then the end");
    }

    /// The heal arm asks for the dead receiver without waiting: a subscription that has not ended
    /// yields none, at once.
    #[tokio::test]
    async fn into_dead_does_not_wait_for_a_subscription_that_has_not_ended() {
        let (_tx, events) = topic();
        let mesh = spawn_split(events, None);

        assert!(mesh.into_dead().is_none(), "the stream has not ended");
    }

    /// A message of the engine's own encoder is JSON: its first byte is never the frame kind.
    #[test]
    fn a_message_of_the_engine_does_not_start_with_the_frame_kind() {
        use habilis_network_iroh_gossip_transport::frame::FRAME_KIND;

        let mesh = crate::protocol::MeshId::from("test");
        let author = crate::testing::nick("alice");
        let answer =
            crate::protocol::Message::new_pong(&mesh, &author, crate::testing::nick("bob"));
        let request = crate::protocol::Message::new_ping(&mesh, &author);
        for message in [answer, request] {
            let bytes = message.serialize().expect("serialize");
            assert_ne!(bytes.first(), Some(&FRAME_KIND), "{bytes:?}");
            assert!(!super::is_frame(&bytes));
        }
    }
}
