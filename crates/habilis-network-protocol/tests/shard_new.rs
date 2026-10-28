//! A shard header is built from outside the crate: the type is `#[non_exhaustive]`, so a struct literal is refused there.

use habilis_network_protocol::{Shard, ShardGroup};
use habilis_network_test_tracing::test;

#[test]
fn a_shard_header_is_built_from_outside_the_crate() {
    let group = ShardGroup::from_uuid_str("b3f1c2d4-5e6a-4b8c-9d0e-1f2a3b4c5d6e").expect("a uuid");
    let shard = Shard::new(group.clone(), 4).with_index(2);
    assert_eq!(shard.group, group, "the group is kept");
    assert_eq!(shard.index, 2, "the index is the one given");
    assert_eq!(shard.total, 4, "the total is the one given");
}

#[test]
fn a_new_shard_header_starts_at_index_zero() {
    let group = ShardGroup::from_uuid_str("b3f1c2d4-5e6a-4b8c-9d0e-1f2a3b4c5d6e").expect("a uuid");
    assert_eq!(Shard::new(group, 3).index, 0, "index 0 until with_index");
}
