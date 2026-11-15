use std::time::Duration;

/// Is something listening and answering here?
///
/// Any reply counts, including an error status: the question is whether the
/// socket is live, not whether this particular path exists.
pub(crate) fn reachable(url: &str) -> bool {
    ureq::get(url)
        .config()
        .timeout_global(Some(Duration::from_secs(1)))
        .build()
        .call()
        .is_ok()
}
