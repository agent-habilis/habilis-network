//! Cut one entry of the per-peer map into merges that each fit one frame.

use std::mem;

use serde_json::{Map, Value};

use crate::DocError;

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
}
