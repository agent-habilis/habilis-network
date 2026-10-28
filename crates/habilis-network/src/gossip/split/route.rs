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
