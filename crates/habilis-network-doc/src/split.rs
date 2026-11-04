//! Cut one entry of the per-peer map into merges that each fit one frame.

use std::mem;

use serde_json::{Map, Value};

use crate::DocError;

/// Cut `entry` into merges of at most `budget` bytes of JSON each. Applied in order, the merges
/// give `entry` again.
///
/// The keys go smallest first, and equal sizes go by key name, so the same entry always gives the
/// same merges. A small field lands in the first merge and a large one after it. An object that is
/// too large for one merge is cut again, key by key, and each part keeps the path of its keys.
///
/// # Errors
/// [`DocError::TooLarge`] when one value that is not an object is larger than `budget`: it
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
/// let merges: Vec<_> = split_entry(&entry, 100).expect("fits").collect();
/// assert_eq!(merges, vec![entry]);
/// ```
pub fn split_entry(
    entry: &Value,
    budget: usize,
) -> Result<impl Iterator<Item = Value> + use<>, DocError> {
    Ok(parts(entry, budget)?.into_iter())
}

/// [`split_entry`], with the merges in a list that the cut of an object can extend.
fn parts(entry: &Value, budget: usize) -> Result<Vec<Value>, DocError> {
    let bytes = json_len(entry);
    if bytes <= budget {
        return Ok(vec![entry.clone()]);
    }
    let Value::Object(fields) = entry else {
        return Err(DocError::TooLarge { bytes, budget });
    };
    let mut ordered: Vec<(&String, &Value)> = fields.iter().collect();
    ordered.sort_by_key(|(key, value)| (json_len(value), key.as_str()));
    let mut chunks: Vec<Value> = Vec::new();
    let mut open = Map::new();
    let mut open_bytes = BRACES;
    for (key, value) in ordered {
        let pair = json_len(&Value::String(key.clone())) + 1 + json_len(value);
        if BRACES + pair > budget {
            flush(&mut open, &mut chunks);
            open_bytes = BRACES;
            let room = budget.saturating_sub(BRACES + json_len(&Value::String(key.clone())) + 1);
            for part in parts(value, room)? {
                chunks.push(Value::Object(Map::from_iter([(key.clone(), part)])));
            }
            continue;
        }
        if open_bytes + pair + 1 > budget {
            flush(&mut open, &mut chunks);
            open_bytes = BRACES;
        }
        open_bytes += pair + 1;
        open.insert(key.clone(), value.clone());
    }
    flush(&mut open, &mut chunks);
    Ok(chunks)
}

/// The bytes of the braces around the fields of an object.
const BRACES: usize = 2;

fn json_len(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(0, |bytes| bytes.len())
}

/// Move the open merge, if it holds a field, to the end of `chunks`.
fn flush(open: &mut Map<String, Value>, chunks: &mut Vec<Value>) {
    if !open.is_empty() {
        chunks.push(Value::Object(mem::take(open)));
    }
}

#[cfg(test)]
mod tests {
    use crate::DocError;
    use serde_json::{Value, json};

    /// The merges of `split_entry`, in a list.
    fn cut(entry: &Value, budget: usize) -> Result<Vec<Value>, DocError> {
        super::split_entry(entry, budget).map(Iterator::collect)
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
            cut(&entry, 1_000).expect("fits"),
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
        let chunks = cut(&entry, 1_000).expect("cuts");
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
        let chunks = cut(&entry, 1_000).expect("cuts");
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
    fn a_value_that_cannot_be_cut_is_refused() {
        let entry = json!({ "card": "c".repeat(2_000) });
        let refused = cut(&entry, 1_000);
        assert!(
            matches!(refused, Err(DocError::TooLarge { .. })),
            "a value that cannot be cut is refused with the size error"
        );
    }

    #[test]
    fn equal_sizes_go_by_key_name_so_the_merges_are_always_the_same() {
        let entry = json!({ "b": "x".repeat(600), "a": "y".repeat(600) });
        let first = cut(&entry, 700).expect("cuts");
        let again = cut(&entry, 700).expect("cuts");
        assert_eq!(first, again, "the same entry gives the same merges");
        assert_eq!(first.len(), 2, "the 2 values go in 2 merges");
        assert!(
            first[0].get("a").is_some() && first[0].get("b").is_none(),
            "the key that sorts first goes first"
        );
    }
}
