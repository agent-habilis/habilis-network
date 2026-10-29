/// Per-frame classification the engine needs to decide retention, push
/// surfacing, and fork/DAG indexing without knowing the app's tag taxonomy.
/// Only meaningful for `MessageKind::App` frames — the engine consults it
/// solely when [`crate::protocol::MessageKind::app_tag`] is `Some`.
///
/// A set of five independent per-frame wire policies, one bit each. Build one with
/// [`AppClass::NONE`](super::AppClass::NONE), the flags, [`AppClass::union`](super::AppClass::union) and [`AppClass::if`](super::AppClass::if).
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
    /// No policy: the frame is not loggable, not a beat, not valid, not chained and not sealed.
    pub const NONE: Self = Self(0);
    /// Goes in the chat message-log / poll-fetch buffer (vs. plumbing like an
    /// RPC request/response, which reaches its caller via a parked waiter).
    pub const LOGGABLE: Self = Self(1 << 0);
    /// A task liveness **beat** — never retained or surfaced via poll/fetch,
    /// only emitted as a progress widget event.
    pub const BEAT: Self = Self(1 << 1);
    /// The payload parses and agrees with its frame (id / addressing / role /
    /// correlation). A failing frame is dropped whole before it surfaces.
    pub const VALID: Self = Self(1 << 2);
    /// Carries a per-author hash chain (`seq`/parents) and so participates in
    /// fork-detection + the cross-author DAG (broadcast chat).
    pub const CHAINED: Self = Self(1 << 3);
    /// Does this frame's directed body arrive **sealed** (encrypted) to the
    /// addressee? When set, a directed frame addressed to us must unseal
    /// (decrypt) or be dropped — the convention an app picks for its directed tags. When
    /// not set, the directed body is plaintext and passes through unchanged (a
    /// consumer with its own data model's explicit choice). Only consulted on the addressee's
    /// directed path; ignored for broadcast/infra frames, which are never
    /// sealed. `sealed: false` is load-bearing for the membership app (membership/app.rs).
    pub const SEALED: Self = Self(1 << 4);

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

    /// Whether the frame goes in the message log ([`AppClass::LOGGABLE`](super::AppClass::LOGGABLE)).
    #[must_use]
    pub fn loggable(self) -> bool {
        self.0 & Self::LOGGABLE.0 != 0
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

    /// Whether the frame is chained ([`AppClass::CHAINED`](super::AppClass::CHAINED)).
    #[must_use]
    pub fn chained(self) -> bool {
        self.0 & Self::CHAINED.0 != 0
    }

    /// Whether the directed body is sealed ([`AppClass::SEALED`](super::AppClass::SEALED)).
    #[must_use]
    pub fn sealed(self) -> bool {
        self.0 & Self::SEALED.0 != 0
    }
}

impl std::ops::BitOr for AppClass {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl std::fmt::Debug for AppClass {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("AppClass");
        debug.field("loggable", &self.loggable());
        debug.field("beat", &self.beat());
        debug.field("valid", &self.valid());
        debug.field("chained", &self.chained());
        debug.field("sealed", &self.sealed());
        debug.finish()
    }
}
