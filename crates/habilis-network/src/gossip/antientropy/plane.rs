/// Which plane a state digest answer takes; part of the serve gate's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Plane {
    Unicast,
    Gossip,
}
