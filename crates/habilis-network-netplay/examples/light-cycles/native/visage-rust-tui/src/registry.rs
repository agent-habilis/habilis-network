use crate::signal_id::SignalId;
use crate::subscriber_id::SubscriberId;
use std::cell::RefCell;
use std::collections::HashSet;

pub(crate) struct Registry {
    /// Every signal's current subscriber set, by id.
    pub(crate) subs: RefCell<Vec<HashSet<SubscriberId>>>,
    /// The tracking window open during a render, if any — `Some` records
    /// every signal read into it; `None` means untracked (setup code, or a
    /// read from outside any render at all).
    pub(crate) current_deps: RefCell<Option<HashSet<SignalId>>>,
    /// Subscribers waiting for [`flush`], deduplicated by id.
    pub(crate) queue: RefCell<Vec<SubscriberId>>,
    pub(crate) queue_set: RefCell<HashSet<SubscriberId>>,
}
