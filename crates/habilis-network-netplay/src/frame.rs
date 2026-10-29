//! Frame numbering.

use std::ops::{Add, AddAssign, Sub};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A simulation frame number.
///
/// Signed, so [`Frame::NULL`] can be a sentinel and so "how far ahead am I"
/// arithmetic can go negative without wrapping. The simulation itself starts
/// at [`Frame::ZERO`].
///
/// The default is [`Frame::ZERO`], not [`Frame::NULL`].
///
/// A frame plus a count is a frame, and a frame minus a frame is a count. A
/// frame plus a frame is not defined, so the two cannot be confused with the
/// delays and the windows that are plain integers beside them.
///
/// On the wire a frame is its number. A negative number is not a frame, so
/// `Serialize` and `Deserialize` both refuse it: the `-1` that older peers
/// sent for "no frame" is a parse error, and [`Frame::NULL`] cannot leave as
/// `-1`.
///
/// # Examples
///
/// A frame keeps its number, and later frames sort after earlier ones.
///
/// ```
/// use habilis_network_netplay::Frame;
///
/// assert_eq!(Frame::new(3).get(), 3);
/// assert!(Frame::new(2) < Frame::new(3));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Frame(i32);

impl Serialize for Frame {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        if self.0 < 0 {
            return Err(S::Error::custom(format!(
                "frame {} is negative, and no frame is an absent field",
                self.0
            )));
        }
        serializer.serialize_i32(self.0)
    }
}

impl<'de> Deserialize<'de> for Frame {
    fn deserialize<Decoder: Deserializer<'de>>(
        deserializer: Decoder,
    ) -> Result<Self, Decoder::Error> {
        use serde::de::Error as _;
        let number = i32::deserialize(deserializer)?;
        if number < 0 {
            return Err(Decoder::Error::custom(format!(
                "frame {number} is negative, and no frame is an absent field"
            )));
        }
        Ok(Self(number))
    }
}

impl Frame {
    /// "No frame" — an empty slot, an un-started queue, or the absence of a
    /// misprediction. Distinct from [`Frame::ZERO`], which is a real frame.
    pub const NULL: Self = Self(-1);

    /// The first frame of a simulation.
    pub const ZERO: Self = Self(0);

    /// The largest frame number.
    pub const MAX: Self = Self(i32::MAX);

    /// The frame with number `number`.
    #[must_use]
    pub fn new(number: i32) -> Self {
        Self(number)
    }

    /// The frame number.
    #[must_use]
    pub fn get(self) -> i32 {
        self.0
    }
}

impl std::fmt::Display for Frame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Add<i32> for Frame {
    type Output = Self;

    fn add(self, count: i32) -> Self {
        Self(self.0 + count)
    }
}

impl AddAssign<i32> for Frame {
    fn add_assign(&mut self, count: i32) {
        self.0 += count;
    }
}

impl Sub<i32> for Frame {
    type Output = Self;

    fn sub(self, count: i32) -> Self {
        Self(self.0 - count)
    }
}

impl Sub for Frame {
    type Output = i32;

    fn sub(self, other: Self) -> i32 {
        self.0 - other.0
    }
}

impl TryFrom<Frame> for usize {
    type Error = std::num::TryFromIntError;

    fn try_from(frame: Frame) -> Result<Self, Self::Error> {
        Self::try_from(frame.0)
    }
}

/// Whether the input handed to the simulation for a frame is the real thing
/// or a guess.
///
/// A predicted input is not an error: it is the normal case for a remote
/// player whose input has not arrived yet, and the session will roll back and
/// re-simulate if the guess turns out wrong. Apps mostly ignore this, but it
/// is worth honouring for effects that shouldn't fire twice — a sound cue on
/// a predicted input may be re-triggered after a rollback.
///
/// # Examples
///
/// A real input and a guessed input have different statuses.
///
/// ```
/// use habilis_network_netplay::InputStatus;
///
/// assert_ne!(InputStatus::Confirmed, InputStatus::Predicted);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InputStatus {
    /// The player's real input for this frame, received and confirmed.
    Confirmed,
    /// A guess. The session predicts by repeating the player's last known
    /// input, which is GGPO's own strategy and the right one for held-button
    /// controls.
    Predicted,
    /// The player has disconnected; this is the neutral default input.
    Disconnected,
}

#[cfg(test)]
mod tests {
    use super::Frame;

    #[test]
    fn a_frame_that_is_a_real_frame_serializes_as_its_number() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            serde_json::to_string(&Frame::new(7)).expect("serializes"),
            "7",
            "a real frame serializes as its number"
        );
        assert_eq!(
            serde_json::to_string(&Frame::ZERO).expect("serializes"),
            "0",
            "the zero frame serializes as its number"
        );
    }

    /// The sentinel is not a frame, so it must not be able to leave in a
    /// packet as `-1`.
    #[test]
    fn the_null_frame_does_not_serialize() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            serde_json::to_string(&Frame::NULL).is_err(),
            "the null frame does not serialize"
        );
    }
}
