//! The handler that admits one consumer to one stream.

use std::sync::Arc;
use std::time::Duration;

use habilis_network::iroh::endpoint::{Connection, SendStream};
use habilis_network::iroh::protocol::{AcceptError, ProtocolHandler};
use habilis_network::net::direct::{PROBE_DEADLINE, PayloadPath, refuse_unless_direct};
use zeroize::Zeroizing;

use super::registry::{Link, Registry};
use crate::code;
use crate::hash::{ID_LEN, SECRET_LEN, StreamId, StreamSecret};

use n0_future::time;
use std::error;
/// How long a connection may take to present `id ‖ secret`. Nothing the peer
/// has proved yet, so it gets no more than a slow link needs.
const PRE_AUTH: Duration = Duration::from_secs(10);

/// The `ProtocolHandler` for [`crate::STREAM_ALPN`]: admit one consumer to one
/// stream and hand its connection to the waiting [`Producer`].
#[derive(Debug, Clone)]
pub(crate) struct StreamAcceptor {
    // the acceptor shares the registry with the node, which holds the producers
    pub(crate) registry: Arc<Registry>,
    pub(crate) relay_transport: PayloadPath,
}

impl ProtocolHandler for StreamAcceptor {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // Before reading a byte, and before the slot is taken: a consumer
        // refused here must not spend the hash.
        if !refuse_unless_direct(
            &connection,
            self.relay_transport,
            PROBE_DEADLINE,
            code::RELAY_REFUSED,
        )
        .await
        {
            return Ok(());
        }
        let Ok(Ok((send, header))) = time::timeout(PRE_AUTH, read_header(&connection)).await else {
            connection.close(code::UNKNOWN.into(), b"no stream request");
            return Ok(());
        };
        let (id, secret) = header;
        match self.registry.claim(&id, &secret) {
            Ok(waiting) => {
                if waiting
                    .send(Link {
                        connection: connection.clone(),
                        send,
                    })
                    .is_err()
                {
                    // The producer went away between the claim and now: the
                    // stream existed and this consumer was admitted, so
                    // abandoned, not unknown. The same answer `Producer::drop`
                    // gives when the link landed before it (its `try_recv`).
                    connection.close(code::ABANDONED.into(), b"abandoned");
                    return Ok(());
                }
                // The producer owns the connection now; this task only keeps
                // the handler alive for its lifetime.
                connection.closed().await;
            }
            Err(refusal) => connection.close(refusal.into(), b"refused"),
        }
        Ok(())
    }
}

async fn read_header(
    connection: &Connection,
) -> Result<(SendStream, (StreamId, StreamSecret)), Box<dyn error::Error + Send + Sync>> {
    let (send, mut recv) = connection.accept_bi().await?;
    let mut id = [0; ID_LEN];
    let mut secret = Zeroizing::new([0; SECRET_LEN]);
    recv.read_exact(&mut id).await?;
    recv.read_exact(&mut *secret).await?;
    Ok((send, (StreamId::from(id), StreamSecret::from(secret))))
}
