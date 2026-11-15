//! The structure of an encoded value: how many units it holds.

/// Counts the units of the encoded JSON `bytes`. A unit is one `{`, `[` or `,` outside a string.
///
/// Each value and each key of a document follows one unit, so a document has at most one node more than it has
/// units. The count is therefore a bound of the RAM of the parsed value. It takes one pass over the bytes and does
/// not parse them.
///
/// The rule is part of the protocol: a pointer carries the count, and every member counts the same way. Do not
/// change it without a bump of the wire version.
///
/// # Examples
///
/// ```
/// use habilis_network_doc::structure_units;
///
/// assert_eq!(structure_units(br#"{"a":[1,2],"b":{"c":3}}"#), 5);
/// ```
#[must_use]
pub fn structure_units(bytes: &[u8]) -> usize {
    let mut units = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'{' | b'[' | b',' => units += 1,
                _ => {}
            }
        }
    }
    units
}

#[cfg(test)]
mod tests {
    #[test]
    fn braces_brackets_and_commas_are_units() {
        assert_eq!(
            super::structure_units(br#"{"a":[1,2],"b":{"c":3}}"#),
            5,
            "the units are the object, the array, 2 commas and the inner object"
        );
    }

    #[test]
    fn an_array_of_small_objects_has_two_units_for_each_object_but_the_first() {
        assert_eq!(
            super::structure_units(br#"{"a":[{"n":1},{"n":1}]}"#),
            5,
            "the second object adds its brace and the comma before it"
        );
    }

    #[test]
    fn a_long_string_adds_no_unit() {
        let text = format!(r#"{{"a":"{}"}}"#, "x".repeat(100_000));
        assert_eq!(
            super::structure_units(text.as_bytes()),
            1,
            "a string costs its RAM in bytes, so it adds no unit to the one of the object"
        );
    }

    #[test]
    fn the_characters_of_a_string_are_no_units() {
        assert_eq!(
            super::structure_units(br#"{"a":"{[,"}"#),
            1,
            "a brace, a bracket and a comma inside a string are text"
        );
    }

    #[test]
    fn an_escaped_quote_does_not_end_a_string() {
        assert_eq!(
            super::structure_units(br#"{"a":"x\", {[,"}"#),
            1,
            "the string goes on after an escaped quote, so what follows it is text"
        );
    }

    #[test]
    fn an_escaped_backslash_before_a_quote_does_end_the_string() {
        assert_eq!(
            super::structure_units(br#"{"a":"x\\","b":1}"#),
            2,
            "the string ends at its quote after an escaped backslash, so the comma that follows is a unit"
        );
    }

    #[test]
    fn empty_input_has_no_unit() {
        assert_eq!(super::structure_units(b""), 0, "no byte can hold a unit");
    }
}
