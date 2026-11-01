//! Base58 of a long input, with the same text as `bs58` and the same inputs accepted.
//!
//! The ids of a digest are one number of up to a few thousand bytes. `bs58` works on one byte
//! and one digit per step, so its cost grows with the square of the length. Here a step takes
//! 32 bits and 5 digits, which is the same number of steps divided by about 20.

use std::iter;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/// The most digits that fit one 32-bit limb as a whole group: 58^5 is below 2^32.
const GROUP_DIGITS: usize = 5;
const GROUP: u64 = 58 * 58 * 58 * 58 * 58;
const NOT_A_DIGIT: u8 = u8::MAX;

const DIGIT_OF: [u8; 256] = {
    let mut table = [NOT_A_DIGIT; 256];
    let mut value = 0u8;
    while (value as usize) < ALPHABET.len() {
        table[ALPHABET[value as usize] as usize] = value;
        value += 1;
    }
    table
};

/// The Base58 text of `bytes`.
pub(super) fn encode(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|&&byte| byte == 0).count();
    let rest = &bytes[zeros..];

    // The number, most significant limb first. `rest` starts with a non-zero byte.
    let head = rest.len() % 4;
    let mut limbs: Vec<u32> = Vec::with_capacity(rest.len().div_ceil(4));
    if head != 0 {
        limbs.push(
            rest[..head]
                .iter()
                .fold(0, |acc, &byte| acc << 8 | u32::from(byte)),
        );
    }
    limbs.extend(
        rest[head..]
            .chunks_exact(4)
            .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])),
    );

    // Divide by 58^5 until nothing is left: each remainder is 5 digits, least significant first.
    let mut digits: Vec<u8> = Vec::with_capacity(rest.len() * 138 / 100 + GROUP_DIGITS);
    let mut start = 0;
    while start < limbs.len() {
        let mut remainder = 0u64;
        for limb in &mut limbs[start..] {
            let value = remainder << 32 | u64::from(*limb);
            *limb = u32::try_from(value / GROUP).expect("the remainder is below the divisor");
            remainder = value % GROUP;
        }
        for _ in 0..GROUP_DIGITS {
            digits.push(ALPHABET[usize::try_from(remainder % 58).expect("below 58")]);
            remainder /= 58;
        }
        while limbs.get(start) == Some(&0) {
            start += 1;
        }
    }
    while digits.last() == Some(&ALPHABET[0]) {
        digits.pop();
    }

    let mut text = String::with_capacity(zeros + digits.len());
    text.extend(iter::repeat_n(char::from(ALPHABET[0]), zeros));
    text.extend(digits.iter().rev().map(|&digit| char::from(digit)));
    text
}

/// The bytes of a Base58 `text`, or `None` if a character is not in the alphabet.
pub(super) fn decode(text: &str) -> Option<Vec<u8>> {
    let characters = text.as_bytes();
    let zeros = characters
        .iter()
        .take_while(|&&character| character == ALPHABET[0])
        .count();
    let rest = &characters[zeros..];

    // The number, least significant limb first: multiply by 58^k and add the next k digits.
    let head = rest.len() % GROUP_DIGITS;
    let mut limbs: Vec<u32> = Vec::with_capacity(rest.len() / GROUP_DIGITS + 1);
    let groups = iter::once(&rest[..head])
        .filter(|group| !group.is_empty())
        .chain(rest[head..].chunks_exact(GROUP_DIGITS));
    for group in groups {
        let mut scale = 1u64;
        let mut carry = 0u64;
        for &character in group {
            let digit = DIGIT_OF[usize::from(character)];
            if digit == NOT_A_DIGIT {
                return None;
            }
            scale *= 58;
            carry = carry * 58 + u64::from(digit);
        }
        for limb in &mut limbs {
            let value = u64::from(*limb) * scale + carry;
            *limb = u32::try_from(value & u64::from(u32::MAX)).expect("masked to 32 bits");
            carry = value >> 32;
        }
        if carry != 0 {
            limbs.push(u32::try_from(carry).expect("below the scale"));
        }
    }

    let mut bytes = vec![0u8; zeros];
    bytes.extend(
        limbs
            .iter()
            .rev()
            .flat_map(|limb| limb.to_be_bytes())
            .skip_while(|&byte| byte == 0),
    );
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{decode, encode};

    const ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    fn reference_decode(text: &str) -> Option<Vec<u8>> {
        bs58::decode(text).into_vec().ok()
    }

    /// Random bytes behind a run of zero bytes, which Base58 writes as leading `1`s.
    fn bytes_with_zero_prefix() -> impl Strategy<Value = Vec<u8>> {
        (0usize..40, prop::collection::vec(any::<u8>(), 0..5000)).prop_map(|(zeros, rest)| {
            let mut bytes = vec![0u8; zeros];
            bytes.extend(rest);
            bytes
        })
    }

    /// Text of the alphabet behind a run of `1`s, and sometimes one character outside it.
    fn text_with_one_prefix() -> impl Strategy<Value = String> {
        let alphabet: Vec<char> = ALPHABET.chars().collect();
        (
            0usize..40,
            prop::collection::vec(prop::sample::select(alphabet), 0..7000),
            prop::option::of((any::<prop::sample::Index>(), "[0OIl é\u{0}]")),
        )
            .prop_map(|(ones, rest, stray)| {
                let mut text = "1".repeat(ones);
                text.extend(rest);
                if let Some((at, stray)) = stray {
                    text.insert_str(at.index(text.len() + 1), &stray);
                }
                text
            })
    }

    proptest! {
        #[test]
        fn encode_gives_what_bs58_gives(bytes in bytes_with_zero_prefix()) {
            prop_assert_eq!(encode(&bytes), bs58::encode(&bytes).into_string());
        }

        #[test]
        fn decode_gives_what_bs58_gives(text in text_with_one_prefix()) {
            prop_assert_eq!(decode(&text), reference_decode(&text));
        }

        #[test]
        fn decode_undoes_encode(bytes in bytes_with_zero_prefix()) {
            prop_assert_eq!(decode(&encode(&bytes)), Some(bytes));
        }
    }

    #[test]
    fn the_edges_match_bs58() {
        let edges: [&[u8]; 6] = [&[], &[0], &[0, 0, 0], &[255], &[0, 0, 1], &[255; 16]];
        for bytes in edges {
            assert_eq!(
                encode(bytes),
                bs58::encode(bytes).into_string(),
                "{bytes:?}"
            );
            assert_eq!(decode(&encode(bytes)), Some(bytes.to_vec()), "{bytes:?}");
        }
        for text in ["", "1", "111", "z", "zzzzzz", "0", "1O1", "é"] {
            assert_eq!(decode(text), reference_decode(text), "{text:?}");
        }
    }
}
