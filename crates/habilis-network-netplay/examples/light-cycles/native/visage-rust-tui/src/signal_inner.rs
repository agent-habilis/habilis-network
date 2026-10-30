use crate::signal_id::SignalId;
use std::cell::RefCell;

pub(crate) struct SignalInner<T> {
    pub(crate) id: SignalId,
    pub(crate) value: RefCell<T>,
}
