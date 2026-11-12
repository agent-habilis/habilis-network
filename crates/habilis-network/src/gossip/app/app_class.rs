use std::{fmt, ops};
/// Per-frame classification the engine needs to decide retention, push
/// surfacing, and fork/DAG indexing without knowing the app's tag taxonomy.
/// Only meaningful for `MessageKind::App` frames — the engine consults it
/// solely when [`crate::protocol::MessageKind::app_tag`] is `Some`.
///
/// A set of independent per-frame wire policies, one bit each. Build one with
/// [`AppClass::NONE`](super::AppClass::NONE), the flags, [`AppClass::union`](super::AppClass::union) and [`AppClass::plus_if`](super::AppClass::plus_if).
///
/// # Examples
///
/// An app class is a set of flags, and two classes combine with the bit-or operator. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::AppClass;
///
/// # fn demo(class: AppClass) -> AppClass {
/// class | class
/// # }
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AppClass(u8);

impl AppClass {
    /// No policy: the frame is not pushed, not a beat and not valid.
    pub const NONE: Self = Self(0);
    /// Pushed to the inbound channel of the in-process consumer (vs. plumbing like an
    /// RPC request/response, which reaches its caller via a parked waiter).
    pub const PUSH: Self = Self(1 << 0);
    /// A task liveness **beat** — never retained or surfaced via poll/fetch,
    /// only emitted as a progress widget event.
    pub const BEAT: Self = Self(1 << 1);
    /// The payload parses and agrees with its frame (id / addressing / role /
    /// correlation). A failing frame is dropped whole before it surfaces.
    pub const VALID: Self = Self(1 << 2);

    /// Both policies at once.
    #[must_use]
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// This policy, plus `flag` when `on`.
    #[must_use]
    pub fn plus_if(
        self,
        flag: Self,
        // true adds flag to the policy, false leaves the policy as it is
        on: bool,
    ) -> Self {
        if on { self.union(flag) } else { self }
    }

    /// Whether the frame is pushed to the inbound channel ([`AppClass::PUSH`](super::AppClass::PUSH)).
    #[must_use]
    pub fn pushable(self) -> bool {
        self.0 & Self::PUSH.0 != 0
    }

    /// Whether the frame is a liveness beat ([`AppClass::BEAT`](super::AppClass::BEAT)).
    #[must_use]
    pub fn beat(self) -> bool {
        self.0 & Self::BEAT.0 != 0
    }

    /// Whether the frame's payload is valid ([`AppClass::VALID`](super::AppClass::VALID)).
    #[must_use]
    pub fn valid(self) -> bool {
        self.0 & Self::VALID.0 != 0
    }
}

impl ops::BitOr for AppClass {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl fmt::Debug for AppClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("AppClass");
        debug.field("pushable", &self.pushable());
        debug.field("beat", &self.beat());
        debug.field("valid", &self.valid());
        debug.finish()
    }
}
