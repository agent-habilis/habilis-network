//! The next hop of each destination, kept while the tables that it came from do not change.

use std::collections::HashMap;

use crate::app_id::AppId;
use crate::next_hop::NextHop;

/// What a cached next hop was computed from: the generation of the topology, and the generation of the states of
/// the hops under the gate. A value is current only while both are the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct CacheKey {
    pub(crate) topology: u64,
    pub(crate) gate: u64,
}

/// One map from destination to its next hop, valid for one [`CacheKey`]. A different key clears the map, so no
/// entry of an older table is ever read.
#[derive(Debug, Default)]
pub(crate) struct NextHopCache {
    key: CacheKey,
    hops: HashMap<AppId, NextHop>,
}

impl NextHopCache {
    /// The next hop of `dst` for `key`: the cached one, or the one that `compute` gives, which is then kept.
    pub(crate) fn get_or_compute(
        &mut self,
        key: CacheKey,
        dst: AppId,
        compute: impl FnOnce() -> NextHop,
    ) -> NextHop {
        if self.key != key {
            self.hops.clear();
            self.key = key;
        }
        *self.hops.entry(dst).or_insert_with(compute)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use iroh::SecretKey;

    use super::{CacheKey, NextHopCache};
    use crate::app_id::AppId;
    use crate::next_hop::NextHop;

    fn id(seed: u8) -> AppId {
        AppId::new(SecretKey::from_bytes(&[seed; 32]).public())
    }

    /// Asks for `dst` and counts the computations.
    fn ask(
        cache: &mut NextHopCache,
        key: CacheKey,
        dst: AppId,
        answer: NextHop,
        calls: &Cell<u32>,
    ) -> NextHop {
        cache.get_or_compute(key, dst, || {
            calls.set(calls.get() + 1);
            answer
        })
    }

    /// The same key computes once for a destination, and each destination has its own value.
    #[test]
    fn a_next_hop_is_computed_once_for_one_key() {
        let _guard = ::habilis_network_test_tracing::init();
        let (first, second, hop) = (id(1), id(2), id(3));
        let key = CacheKey {
            topology: 1,
            gate: 1,
        };
        let calls = Cell::new(0);
        let mut cache = NextHopCache::default();

        let computed = ask(&mut cache, key, first, NextHop::Forward(hop), &calls);
        let kept = ask(&mut cache, key, first, NextHop::Unreachable, &calls);
        let other = ask(&mut cache, key, second, NextHop::Unreachable, &calls);

        assert_eq!(
            (computed, kept),
            (NextHop::Forward(hop), NextHop::Forward(hop)),
            "the second ask reads the cache"
        );
        assert_eq!(
            other,
            NextHop::Unreachable,
            "another destination is computed"
        );
        assert_eq!(calls.get(), 2, "one computation for each destination");
    }

    /// A cached next hop is not used after the generation of the topology moved: the vector of the hop can have
    /// expired.
    #[test]
    fn a_next_hop_is_not_used_after_the_topology_moved() {
        let _guard = ::habilis_network_test_tracing::init();
        let (dst, hop) = (id(1), id(2));
        let calls = Cell::new(0);
        let mut cache = NextHopCache::default();
        let before = CacheKey {
            topology: 1,
            gate: 1,
        };
        ask(&mut cache, before, dst, NextHop::Forward(hop), &calls);

        let after = CacheKey {
            topology: 2,
            gate: 1,
        };
        let answer = ask(&mut cache, after, dst, NextHop::Unreachable, &calls);

        assert_eq!(answer, NextHop::Unreachable, "the old value is not read");
        assert_eq!(calls.get(), 2, "the value was computed again");
    }

    /// A cached next hop is not used after the set of refused hops moved: the gate refuses the hop now.
    #[test]
    fn a_next_hop_is_not_used_after_the_refused_set_moved() {
        let _guard = ::habilis_network_test_tracing::init();
        let (dst, hop) = (id(1), id(2));
        let calls = Cell::new(0);
        let mut cache = NextHopCache::default();
        let before = CacheKey {
            topology: 1,
            gate: 1,
        };
        ask(&mut cache, before, dst, NextHop::Forward(hop), &calls);

        let after = CacheKey {
            topology: 1,
            gate: 2,
        };
        let answer = ask(&mut cache, after, dst, NextHop::Unreachable, &calls);

        assert_eq!(answer, NextHop::Unreachable, "the old value is not read");
        assert_eq!(calls.get(), 2, "the value was computed again");
    }
}
