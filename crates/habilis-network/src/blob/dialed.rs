use iroh::endpoint::Connection;

use super::close_on_drop::CloseOnDrop;

/// A connection, and the endpoint of the hedge when the hedge won. The connection lives on that
/// endpoint, so it stays open until the transfer ends.
pub(super) struct Dialed {
    pub(super) connection: Connection,
    pub(super) hedge: Option<CloseOnDrop>,
}

impl Dialed {
    /// Close the endpoint of the hedge, if the hedge won.
    pub(super) async fn close(self) {
        if let Some(hedge) = self.hedge {
            hedge.close().await;
        }
    }
}
