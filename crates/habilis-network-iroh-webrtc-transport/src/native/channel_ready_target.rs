use str0m::channel::ChannelId;

pub(crate) enum ChannelReadyTarget {
    Offerer(ChannelId),
    Answerer,
}
