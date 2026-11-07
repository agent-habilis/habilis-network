//! Cut one entry of the per-peer map into merges that each fit one frame.

use std::mem;

use serde_json::{Map, Value};

use crate::DocError;
use crate::left_out::LeftOut;

/// Cut `entry` into merges that `fits` accepts. Applied in order, the merges give `entry` again,
/// except for a value that cannot be cut: its item is an error, and the other items are still there.
///
/// `fits` takes one merge and says whether its frame is small enough. The caller measures the real
/// frame, signed and sealed, so the cut follows what the wire takes and not a guess. A merge that
/// reaches `fits` is the part itself, with the keys of its path around it.
///
/// The keys go smallest first, and equal sizes go by key name, so the same entry always gives the
/// same merges. A small field lands in the first merge and a large one after it. An object that is
/// too large for one merge is cut again, key by key, and each part keeps the path of its keys.
///
/// # Errors
/// An item is [`DocError::TooLarge`] when one value that is not an object does not fit: it
/// cannot be cut.
///
/// # Examples
///
/// An entry that fits is one merge.
///
/// ```
/// use habilis_network_doc::split_entry;
/// use serde_json::json;
///
/// let entry = json!({ "status": "idle" });
/// let merges: Vec<_> = split_entry(&entry, |merge| merge.to_string().len() <= 100).collect();
/// assert_eq!(merges.len(), 1);
/// ```
pub fn split_entry<Fits: FnMut(&Value) -> bool>(
    entry: &Value,
    mut fits: Fits,
) -> impl Iterator<Item = Result<Value, DocError>> + use<Fits> {
    let mut cuts: Vec<Result<Value, DocError>> = Vec::new();
    cut(entry, &|part| part, &mut fits, &mut cuts);
    cuts.into_iter()
}

/// Pack the leaves of `entry` into merges that `fits` accepts, a seed of the state document. A leaf
/// is a value that is not an object, or an empty object. The leaves go in the order of their paths
/// (the keys of each level sorted by name), and each merge holds consecutive leaves with the keys
/// around them, so a merge is full whatever the shape of the tree. Applied in order, the merges give
/// `entry` again, except for a leaf that cannot fit a frame: its item is an error, and the other
/// items are still there.
///
/// `fits` takes one merge and says whether its frame is small enough, as for [`split_entry`]. The
/// function asks it only near the edge of a merge: it starts from the size of the merge before,
/// and looks for the largest count of leaves that fits from there, so a seed of N leaves costs a
/// few calls for each merge and not one for each leaf. A merge that the limit of paths closes holds
/// at least `129 - D` paths, where `D` is the depth of the tree, of which at most `D - 1` are the
/// keys that it repeats from the merge before, so the merges are at most `P / (130 - 2 x D) + 1`
/// for `P` paths in all (the bound of a limit of bytes is `2 x B / budget + 1`).
///
/// # Errors
/// An item is [`DocError::TooLarge`] when one leaf, with its keys, does not fit a frame.
///
/// # Examples
///
/// Two leaves in a frame of 100 bytes make one merge.
///
/// ```
/// use habilis_network_doc::pack_entry;
/// use serde_json::json;
///
/// let entry = json!({ "a": { "x": 1, "y": 2 } });
/// let merges: Vec<_> = pack_entry(&entry, |merge| merge.to_string().len() <= 100).collect();
/// assert_eq!(merges.len(), 1);
/// ```
pub fn pack_entry<Fits: FnMut(&Value) -> bool>(
    entry: &Value,
    mut fits: Fits,
) -> impl Iterator<Item = Result<Value, DocError>> + use<Fits> {
    let mut packed: Vec<Result<Value, DocError>> = Vec::new();
    pack(entry, &mut fits, &mut packed, &mut LeftOut::default());
    packed.into_iter()
}

/// [`pack_entry`] for a seed: the merges of the leaves that fit, and the leaves that no frame can
/// carry, which are left out. A seed with a leaf less is a seed; a cut that fails on that leaf
/// fails again on every node for ever, since the leaf stays in the document.
pub(crate) fn pack_carryable<Fits: FnMut(&Value) -> bool>(
    entry: &Value,
    mut fits: Fits,
) -> (Vec<Value>, LeftOut) {
    let mut packed: Vec<Result<Value, DocError>> = Vec::new();
    let mut left_out = LeftOut::default();
    pack(entry, &mut fits, &mut packed, &mut left_out);
    let merges: Vec<Value> = packed.into_iter().filter_map(Result::ok).collect();
    (merges, left_out)
}

/// One leaf of an entry: the keys on the way to it, and its value.
type Leaf = (Vec<String>, Value);

fn pack(
    entry: &Value,
    fits: &mut dyn FnMut(&Value) -> bool,
    packed: &mut Vec<Result<Value, DocError>>,
    left_out: &mut LeftOut,
) {
    let mut leaves: Vec<Leaf> = Vec::new();
    collect_leaves(entry, &mut Vec::new(), &mut leaves);
    if leaves.is_empty() {
        packed.push(Ok(entry.clone()));
        return;
    }
    let mut start = 0;
    let mut hint = 1;
    while start < leaves.len() {
        let count = largest_fitting(&leaves[start..], hint, fits);
        if count == 0 {
            let bytes = json_len(&merge_of(&leaves[start..=start]));
            packed.push(Err(DocError::TooLarge { bytes }));
            left_out.count = left_out.count.saturating_add(1);
            left_out
                .first
                .get_or_insert_with(|| leaves[start].0.clone());
            start += 1;
            continue;
        }
        packed.push(Ok(merge_of(&leaves[start..start + count])));
        hint = count;
        start += count;
    }
}

/// The leaves of `value` in the order of their paths, with `prefix` before each path.
fn collect_leaves(value: &Value, prefix: &mut Vec<String>, leaves: &mut Vec<Leaf>) {
    match value {
        Value::Object(fields) if !fields.is_empty() => {
            let mut names: Vec<&String> = fields.keys().collect();
            names.sort();
            for name in names {
                prefix.push(name.clone());
                collect_leaves(&fields[name], prefix, leaves);
                prefix.pop();
            }
        }
        Value::Object(_)
        | Value::Null
        | Value::Bool(_)
        | Value::Number(_)
        | Value::String(_)
        | Value::Array(_) => leaves.push((prefix.clone(), value.clone())),
    }
}

/// The merge that writes `leaves`, each with the keys around it.
fn merge_of(leaves: &[Leaf]) -> Value {
    let mut root = Map::new();
    for (path, value) in leaves {
        insert_at(&mut root, path, value);
    }
    Value::Object(root)
}

fn insert_at(map: &mut Map<String, Value>, path: &[String], value: &Value) {
    let Some((key, rest)) = path.split_first() else {
        return;
    };
    if rest.is_empty() {
        map.insert(key.clone(), value.clone());
        return;
    }
    let slot = map
        .entry(key.clone())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Value::Object(inner) = slot {
        insert_at(inner, rest, value);
    }
}

/// The largest count of leaves, from the first of `leaves`, whose merge `fits` accepts. The search
/// starts at `hint` (the count of the merge before): it tests the hint, goes up or down by steps
/// that double, and then halves the gap, so a run of merges of one size costs 2 calls for each.
fn largest_fitting(leaves: &[Leaf], hint: usize, fits: &mut dyn FnMut(&Value) -> bool) -> usize {
    let mut fit = |count: usize| fits(&merge_of(&leaves[..count]));
    let guess = hint.clamp(1, leaves.len());
    let mut low = 0;
    let mut high = leaves.len() + 1;
    if fit(guess) {
        low = guess;
        let mut step = 1;
        while low < leaves.len() {
            let next = (low + step).min(leaves.len());
            if fit(next) {
                low = next;
                step *= 2;
            } else {
                high = next;
                break;
            }
        }
        if low == leaves.len() {
            return low;
        }
    } else {
        high = guess;
        let mut step = 1;
        while high > 1 {
            let next = high.saturating_sub(step).max(1);
            if fit(next) {
                low = next;
                break;
            }
            high = next;
            step *= 2;
        }
    }
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        if fit(middle) {
            low = middle;
        } else {
            high = middle;
        }
    }
    low
}

/// Cut `value`, whose parts sit inside the keys that `wrap` puts around them.
fn cut(
    value: &Value,
    wrap: &dyn Fn(Value) -> Value,
    fits: &mut dyn FnMut(&Value) -> bool,
    cuts: &mut Vec<Result<Value, DocError>>,
) {
    if fits(&wrap(value.clone())) {
        cuts.push(Ok(wrap(value.clone())));
        return;
    }
    let Value::Object(fields) = value else {
        cuts.push(Err(DocError::TooLarge {
            bytes: json_len(value),
        }));
        return;
    };
    let mut ordered: Vec<(&String, &Value)> = fields.iter().collect();
    ordered.sort_by_key(|(name, part)| (json_len(part), name.as_str()));
    let mut open = Map::new();
    for (key, field) in ordered {
        let mut trial = open.clone();
        trial.insert(key.clone(), field.clone());
        if fits(&wrap(Value::Object(trial))) {
            open.insert(key.clone(), field.clone());
            continue;
        }
        flush(&mut open, wrap, cuts);
        let alone = Value::Object(Map::from_iter([(key.clone(), field.clone())]));
        if fits(&wrap(alone)) {
            open.insert(key.clone(), field.clone());
            continue;
        }
        let inside = |part: Value| wrap(Value::Object(Map::from_iter([(key.clone(), part)])));
        cut(field, &inside, fits, cuts);
    }
    flush(&mut open, wrap, cuts);
}

fn json_len(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(0, |bytes| bytes.len())
}

/// Move the open merge, if it holds a field, to the end of `cuts`.
fn flush(
    open: &mut Map<String, Value>,
    wrap: &dyn Fn(Value) -> Value,
    cuts: &mut Vec<Result<Value, DocError>>,
) {
    if !open.is_empty() {
        cuts.push(Ok(wrap(Value::Object(mem::take(open)))));
    }
}

#[cfg(test)]
mod tests {
    use crate::DocError;
    use serde_json::{Value, json};

    /// The merges of `split_entry` for a frame of `budget` bytes of JSON, in a list.
    fn cut(entry: &Value, budget: usize) -> Vec<Result<Value, DocError>> {
        super::split_entry(entry, |merge| size(merge) <= budget).collect()
    }

    /// The merges of `cut` when none is refused.
    fn merges(entry: &Value, budget: usize) -> Vec<Value> {
        let cuts = cut(entry, budget);
        cuts.into_iter()
            .map(|merge| merge.expect("every part fits"))
            .collect()
    }

    /// RFC 7386 merge of `patch` into `target`.
    fn merge(target: &mut Value, patch: &Value) {
        let Value::Object(fields) = patch else {
            *target = patch.clone();
            return;
        };
        if !target.is_object() {
            *target = json!({});
        }
        let Some(map) = target.as_object_mut() else {
            return;
        };
        for (key, value) in fields {
            let slot = map.entry(key.clone()).or_insert(Value::Null);
            merge(slot, value);
        }
    }

    /// Whether a part, with the keys of the map and the owner around it, is inside a frame.
    fn fits_a_frame(part: &Value) -> bool {
        size(&json!({ "peers": { "alice": part } })) <= 3_400
    }

    fn size(value: &Value) -> usize {
        serde_json::to_vec(value).map_or(0, |bytes| bytes.len())
    }

    fn joined(chunks: &[Value]) -> Value {
        let mut whole = json!({});
        for chunk in chunks {
            merge(&mut whole, chunk);
        }
        whole
    }

    #[test]
    fn an_entry_that_fits_is_one_merge() {
        let entry = json!({ "card": "c", "status": "idle" });
        assert_eq!(
            merges(&entry, 1_000),
            vec![entry],
            "an entry that fits is not cut"
        );
    }

    #[test]
    fn a_large_entry_is_cut_into_merges_that_fit_and_join_into_the_entry() {
        let entry = json!({
            "card": "c".repeat(700),
            "host": "h".repeat(600),
            "status": "idle",
            "cwd": "w".repeat(650),
        });
        let chunks = merges(&entry, 1_000);
        assert!(chunks.len() >= 3, "{} chunks", chunks.len());
        assert!(
            chunks.iter().all(|chunk| size(chunk) <= 1_000),
            "each merge fits the budget"
        );
        assert_eq!(joined(&chunks), entry, "the merges join into the entry");
        assert!(
            chunks[0].get("status").is_some(),
            "the smallest field goes in the first merge"
        );
    }

    #[test]
    fn an_object_that_is_too_large_is_cut_again_and_keeps_its_path() {
        let entry = json!({ "card": { "a": "a".repeat(700), "b": "b".repeat(700) } });
        let chunks = merges(&entry, 1_000);
        assert_eq!(chunks.len(), 2, "the object is cut in 2 merges");
        assert!(
            chunks.iter().all(|chunk| size(chunk) <= 1_000),
            "each merge fits the budget"
        );
        assert_eq!(joined(&chunks), entry, "the merges join into the entry");
        let first_card = chunks[0].get("card");
        assert!(
            first_card.is_some_and(|card| card.get("a").is_some()),
            "the first merge keeps the path of its key"
        );
    }

    #[test]
    fn a_value_that_cannot_be_cut_is_refused_and_the_other_fields_are_still_written() {
        let entry = json!({ "small": "s", "big": "c".repeat(2_000) });
        let cuts = cut(&entry, 1_000);
        assert_eq!(cuts.len(), 2, "one merge and one refusal");
        assert!(
            matches!(&cuts[0], Ok(merge) if merge == &json!({ "small": "s" })),
            "the field that fits is written"
        );
        assert!(
            matches!(&cuts[1], Err(DocError::TooLarge { bytes }) if *bytes > 2_000),
            "the value that cannot be cut is refused with its size"
        );
    }

    /// The caller measures the frame with the keys of the map and the owner around the part, and a
    /// leaf that fits there is not cut, however large it is next to a budget of a fixed size.
    #[test]
    fn a_leaf_is_measured_with_its_keys_around_it_and_is_not_cut_if_it_fits() {
        let extensions: Vec<Value> = (0..5)
            .map(|index| json!({ "uri": format!("https://example.invalid/{index}"), "params": "p".repeat(160) }))
            .collect();
        let entry = json!({
            "card": { "capabilities": { "extensions": extensions }, "name": "alice", "skills": "s".repeat(2_500) },
            "status": "idle",
        });
        let frame = fits_a_frame;
        let cuts: Vec<Result<Value, DocError>> = super::split_entry(&entry, frame).collect();
        let parts: Vec<Value> = cuts
            .into_iter()
            .map(|part| part.expect("every part fits"))
            .collect();
        assert!(
            parts.len() >= 2,
            "the entry is over one frame: {} parts",
            parts.len()
        );
        assert!(
            parts.iter().all(fits_a_frame),
            "each part fits with its keys around it"
        );
        assert_eq!(joined(&parts), entry, "the parts join into the entry");
        let leaf_items = |part: &Value| -> usize {
            let leaf = part.pointer("/card/capabilities/extensions");
            leaf.and_then(Value::as_array).map_or(0, Vec::len)
        };
        let leaf_whole = parts.iter().any(|part| leaf_items(part) == 5);
        assert!(leaf_whole, "the array leaf of about 1 KB is in one part");
    }

    #[test]
    fn equal_sizes_go_by_key_name_so_the_merges_are_always_the_same() {
        let entry = json!({ "b": "x".repeat(600), "a": "y".repeat(600) });
        let first = merges(&entry, 700);
        let again = merges(&entry, 700);
        assert_eq!(first, again, "the same entry gives the same merges");
        assert_eq!(first.len(), 2, "the 2 values go in 2 merges");
        assert!(
            first[0].get("a").is_some() && first[0].get("b").is_none(),
            "the key that sorts first goes first"
        );
    }

    /// The merges that the packing of a seed gives for `entry`, with a frame that `fits`.
    fn pack<Fits: FnMut(&Value) -> bool>(
        entry: &Value,
        fits: Fits,
    ) -> Vec<Result<Value, DocError>> {
        super::pack_entry(entry, fits).collect()
    }

    /// The paths of a merge: every key at every level.
    fn count_paths(value: &Value) -> usize {
        match value {
            Value::Object(fields) => fields.values().map(|field| 1 + count_paths(field)).sum(),
            Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::String(_)
            | Value::Array(_) => 0,
        }
    }

    /// A frame of a seed: at most 128 paths, and no limit of bytes.
    fn seed_frame(merge: &Value) -> bool {
        count_paths(merge) <= 128
    }

    /// The merges of `pack` when none is refused.
    fn packed(entry: &Value, fits: impl FnMut(&Value) -> bool) -> Vec<Value> {
        let items = pack(entry, fits);
        items
            .into_iter()
            .map(|item| item.expect("every part fits"))
            .collect()
    }

    /// The most keys on the way to a leaf of `value`, counting the key of the leaf.
    fn depth_of(value: &Value) -> usize {
        match value {
            Value::Object(fields) if !fields.is_empty() => {
                1 + fields.values().map(depth_of).max().unwrap_or(0)
            }
            Value::Object(_)
            | Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::String(_)
            | Value::Array(_) => 0,
        }
    }

    /// The number of merges that a seed of `paths` paths at depth `depth` needs, at most: a merge
    /// that the path limit closes holds `130 - 2 x depth` paths that no other merge holds, and the
    /// last merge is one more.
    fn frame_bound(paths: usize, depth: usize) -> usize {
        paths.div_ceil(130 - 2 * depth) + 1
    }

    #[test]
    fn a_scalar_beside_a_large_child_does_not_cost_a_frame_of_its_own() {
        let mut big = serde_json::Map::new();
        for leaf in 0..127 {
            big.insert(format!("l{leaf:03}"), json!(leaf));
        }
        let entry = json!({ "a": { "big": Value::Object(big), "x": 1 } });
        let frames = packed(&entry, seed_frame);
        assert_eq!(
            frames.len(),
            2,
            "130 paths need 2 frames of 128, and a frame holds the scalar with the first leaves"
        );
        assert_eq!(joined(&frames), entry, "the merges join into the entry");
    }

    #[test]
    fn a_chain_of_12_levels_with_a_scalar_at_each_level_packs_into_the_bound() {
        let mut leaves = serde_json::Map::new();
        for leaf in 0..128 {
            leaves.insert(format!("l{leaf:03}"), json!(leaf));
        }
        let mut level = Value::Object(leaves);
        for depth in (0..12).rev() {
            level = json!({ format!("s{depth:02}"): 1, "c": level });
        }
        let frames = packed(&level, seed_frame);
        let bound = frame_bound(count_paths(&level), depth_of(&level));
        assert!(
            frames.len() <= bound,
            "{} frames for {} paths at depth {}, the bound is {bound}",
            frames.len(),
            count_paths(&level),
            depth_of(&level)
        );
        assert!(
            frames.iter().all(seed_frame),
            "each merge is inside the path limit"
        );
        assert_eq!(joined(&frames), level, "the merges join into the entry");
    }

    /// A small deterministic generator, so a failing seed can be run again.
    struct Dice(u64);

    impl Dice {
        fn below(&mut self, bound: usize) -> usize {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let wide = u64::try_from(bound).expect("a bound");
            usize::try_from((self.0 >> 33) % wide).expect("a small number")
        }
    }

    /// A random tree: an object of 1 to 3 keys, each a leaf or an object, down to `levels` levels.
    fn tree(dice: &mut Dice, levels: usize) -> Value {
        let mut fields = serde_json::Map::new();
        let width = 1 + dice.below(3);
        for key in 0..width {
            let leaf = levels == 1 || dice.below(3) == 0;
            let value = if leaf {
                json!(dice.below(1000))
            } else {
                tree(dice, levels - 1)
            };
            fields.insert(format!("k{key}"), value);
        }
        Value::Object(fields)
    }

    #[test]
    fn the_merges_of_200_random_trees_stay_inside_the_bound_and_join_into_the_tree() {
        let mut dice = Dice(7);
        let mut deepest = 0;
        let mut widest = 0;
        for seed in 0..200 {
            let levels = 1 + dice.below(12);
            let mut root = serde_json::Map::new();
            let tops = 1 + dice.below(60);
            for top in 0..tops {
                root.insert(format!("t{top:02}"), tree(&mut dice, levels));
            }
            let entry = Value::Object(root);
            deepest = deepest.max(depth_of(&entry));
            widest = widest.max(count_paths(&entry));
            let frames = packed(&entry, seed_frame);
            let bound = frame_bound(count_paths(&entry), depth_of(&entry));
            assert!(
                frames.len() <= bound,
                "tree {seed}: {} frames for {} paths at depth {}, the bound is {bound}",
                frames.len(),
                count_paths(&entry),
                depth_of(&entry)
            );
            assert!(
                frames.iter().all(seed_frame),
                "tree {seed}: each merge is inside the path limit"
            );
            assert_eq!(
                joined(&frames),
                entry,
                "tree {seed}: the merges join into the tree"
            );
        }
        assert!(
            deepest >= 10 && widest >= 400,
            "the draws reach deep and wide trees: depth {deepest}, paths {widest}"
        );
    }

    #[test]
    fn a_leaf_larger_than_a_frame_is_an_item_with_an_error_and_the_other_leaves_are_packed() {
        let entry = json!({ "a": 1, "b": "x".repeat(2_000), "c": 3 });
        let items = pack(&entry, |merge| size(merge) <= 500);
        let errors = items.iter().filter(|item| item.is_err());
        let refused = errors.count();
        assert_eq!(refused, 1, "the leaf b is the one refusal");
        assert!(
            items
                .iter()
                .any(|item| matches!(item, Err(DocError::TooLarge { bytes }) if *bytes > 2_000)),
            "the refusal names the size of the leaf"
        );
        let kept: Vec<Value> = items.into_iter().filter_map(Result::ok).collect();
        assert_eq!(
            joined(&kept),
            json!({ "a": 1, "c": 3 }),
            "the leaves that fit are packed"
        );
    }

    #[test]
    fn leaves_of_one_size_fill_the_frames_by_bytes_and_the_same_entry_gives_the_same_merges() {
        let mut leaves = serde_json::Map::new();
        for leaf in 0..200 {
            leaves.insert(format!("l{leaf:03}"), json!("v".repeat(40)));
        }
        let entry = json!({ "live": Value::Object(leaves) });
        let frames = packed(&entry, |merge| size(merge) <= 1_000);
        let again = packed(&entry, |merge| size(merge) <= 1_000);
        assert_eq!(frames, again, "the same entry gives the same merges");
        let last = frames.len() - 1;
        let numbered = frames.iter().enumerate();
        for (position, frame) in numbered {
            assert!(size(frame) <= 1_000, "merge {position} fits the budget");
            assert!(
                position == last || size(frame) > 900,
                "merge {position} is full: {} bytes",
                size(frame)
            );
        }
        assert_eq!(joined(&frames), entry, "the merges join into the entry");
    }
}
