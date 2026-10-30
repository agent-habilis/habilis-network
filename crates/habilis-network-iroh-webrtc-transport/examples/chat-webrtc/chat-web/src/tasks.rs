use crate::{Emitter, Event, describe, event_of, read_msg, write_msg};
use chat_proto::{ClientMsg, ServerMsg};
use futures::channel::mpsc;
use habilis_network_iroh_webrtc_transport::iroh::endpoint;
use habilis_network_iroh_webrtc_transport::iroh::endpoint::RecvStream;

/// Drain the room's messages into the tab's callback.
pub(crate) fn spawn_reader(mut recv: RecvStream, emit: Emitter) {
    wasm_bindgen_futures::spawn_local(async move {
        loop {
            match read_msg::<ServerMsg>(&mut recv).await {
                Ok(message) => emit.send(&event_of(&message)),
                Err(error) => {
                    emit.send(&Event::Closed {
                        reason: describe(&error),
                    });
                    return;
                }
            }
        }
    });
}

/// Drain the outbox onto the stream.
pub(crate) fn spawn_writer(
    mut send: endpoint::SendStream,
    emit: Emitter,
) -> mpsc::UnboundedSender<String> {
    use futures::StreamExt as _;
    let (tx, mut rx) = mpsc::unbounded::<String>();
    wasm_bindgen_futures::spawn_local(async move {
        while let Some(text) = rx.next().await {
            let message = ClientMsg::Say { text };
            if let Err(error) = write_msg(&mut send, &message).await {
                emit.send(&Event::Closed {
                    reason: describe(&error),
                });
                return;
            }
        }
    });
    tx
}
