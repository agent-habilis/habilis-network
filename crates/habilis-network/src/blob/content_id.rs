/// An opaque content-group id the blob layer keys evictable blobs by.
///
/// Whatever the application groups content by — a task, a job, a conversation —
/// it maps into this; the blob layer never names that type. `evict_content` then
/// drops a whole group at once.
///
/// # Examples
///
/// A content id names the content of a blob.
///
/// ```
/// use habilis_network::ops::blob::ContentId;
///
/// let _id = ContentId::new("abc");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContentId(String);

impl ContentId {
    /// Wraps `id` as it is. Nothing is checked.
    #[must_use]
    pub fn new(id: &str) -> Self {
        Self(id.to_owned())
    }
}
