use str0m::channel::ChannelId;

#[derive(Clone)]
pub(crate) enum ChannelReadyTarget {
    Offerer(ChannelId),
    Answerer,
}
