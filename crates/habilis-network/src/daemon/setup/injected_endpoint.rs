use anyhow::Result;

use crate::daemon::setup_error::SetupError;
use iroh::Endpoint;

use crate::protocol::mesh::LookupOpts;

/// An endpoint the caller already built, shared with the mesh.
///
/// Lets one process run an application protocol and a mesh node on **one**
/// identity instead of two. Without it a process that does both appears on the
/// network as two unrelated peers — which, among other things, makes any
/// per-peer count wrong: the same machine is reachable twice and there is
/// nothing to deduplicate on.
///
/// The fields are private, so [`InjectedEndpoint::bind`] is the only way to make
/// one. It installs the transports and binds the endpoint in one step, and the
/// connection hook reports to the admission table that it makes. The mesh checks
/// the rest when it is set up, because only then is the mesh known. The
/// `LookupOpts` given to `bind` must also match the ones the mesh id derives, or
/// the relay-direct rendezvous dial has no rung to ride.
///
/// A literal does not compile outside this module:
///
/// ```compile_fail,E0451
/// # use habilis_network::runtime::InjectedEndpoint;
/// # fn literal() -> InjectedEndpoint {
/// InjectedEndpoint { ..todo!() }
/// # }
/// ```
///
/// The constructor is the one that compiles:
///
/// ```no_run
/// # use habilis_network::net::TransportHandles;
/// # use habilis_network::runtime::InjectedEndpoint;
/// # use habilis_network::protocol::mesh::LookupOpts;
/// # async fn build() -> anyhow::Result<InjectedEndpoint> {
/// let secret = habilis_network::iroh::SecretKey::from_bytes(&[1; 32]);
/// InjectedEndpoint::bind(
///     &LookupOpts::loopback(),
///     secret,
///     Vec::new(),
///     TransportHandles::default(),
///     64,
/// )
/// .await
/// .map_err(anyhow::Error::from)
/// # }
/// ```
pub struct InjectedEndpoint {
    pub(super) endpoint: Endpoint,
    pub(super) webrtc: habilis_network_iroh_webrtc_transport::WebRtcHandle,
    /// The multi-hop handle the endpoint was built with. `None` leaves this
    /// node without multi-hop, whatever the mesh policy allows: a transport
    /// cannot be added to an endpoint that is already bound. Only the host branch of
    /// `build_member_endpoint` reads it, so a browser build does not keep it.
    #[cfg(all(feature = "multihop", feature = "host"))]
    pub(super) multihop: Option<habilis_network_iroh_multihop_transport::MultihopHandle>,
    /// The admission table the endpoint's connection hook reports to. The mesh
    /// enforces its direct-peer cap on this table, so a table made elsewhere would
    /// get no report from the hook.
    pub(super) admission: crate::transport::SignalAdmission,
    /// The handle of the mDNS address lookup of the endpoint, when `bind` wired one.
    /// The mesh hears the other members of its mesh on the LAN through it, and marks
    /// the endpoint as a member in the record it announces.
    pub(super) mdns: Option<crate::lookup::MdnsHandle>,
}

impl InjectedEndpoint {
    /// Binds an endpoint on `secret` with the transports of `transports`, and
    /// makes the admission table that its connection hook reports to.
    ///
    /// The keys of the handles are checked before anything is bound, so a
    /// refused handle is not spent on an endpoint. `max_direct` is the ceiling of
    /// direct connections, as in [`SetupParams::max_direct`](super::SetupParams::max_direct).
    ///
    /// # Errors
    /// `transports` has no WebRTC handle, or it already has an admission table
    /// (this method makes the one). A handle was made from a key other than the one
    /// that `secret` derives, or the endpoint does not bind.
    pub async fn bind(
        lookups: &LookupOpts,
        secret: iroh::SecretKey,
        alpns: Vec<Vec<u8>>,
        transports: crate::lookup::TransportHandles,
        max_direct: usize,
    ) -> Result<Self, SetupError> {
        Self::bind_checked(lookups, secret, alpns, transports, max_direct)
            .await
            .map_err(SetupError::internal)
    }

    pub(super) async fn bind_checked(
        lookups: &LookupOpts,
        secret: iroh::SecretKey,
        alpns: Vec<Vec<u8>>,
        mut transports: crate::lookup::TransportHandles,
        max_direct: usize,
    ) -> Result<Self> {
        anyhow::ensure!(
            transports.admission.is_none(),
            "an injected endpoint makes its own admission table: pass `max_direct`, not a table"
        );
        let webrtc = transports
            .webrtc
            .clone()
            .ok_or_else(|| anyhow::anyhow!("an injected endpoint needs a WebRTC transport"))?;
        let bound = secret.public();
        super::check_webrtc_key(bound, &webrtc)?;
        #[cfg(feature = "multihop")]
        super::check_hop_key(bound, transports.multihop.as_ref())?;
        let admission = crate::transport::SignalAdmission::new(max_direct);
        transports.admission = Some(admission.clone());
        #[cfg(all(feature = "multihop", feature = "host"))]
        let multihop = transports.multihop.clone();
        let (endpoint, mdns) = crate::lookup::build_endpoint_keeping_mdns(
            lookups,
            Some(secret),
            None,
            alpns,
            transports,
        )
        .await?;
        Ok(Self {
            endpoint,
            webrtc,
            #[cfg(all(feature = "multihop", feature = "host"))]
            multihop,
            admission,
            mdns,
        })
    }
}

impl InjectedEndpoint {
    /// A copy of the mDNS handle. Where mDNS is compiled in the handle is a clonable lookup, and
    /// where it is not the handle is `Infallible`, which is `Copy`: one `clone` call cannot suit
    /// both builds.
    #[cfg(all(feature = "host", feature = "mdns"))]
    pub(super) fn mdns_handle(&self) -> Option<crate::lookup::MdnsHandle> {
        self.mdns.clone()
    }

    #[cfg(all(feature = "host", not(feature = "mdns")))]
    pub(super) fn mdns_handle(&self) -> Option<crate::lookup::MdnsHandle> {
        self.mdns
    }
}

impl std::fmt::Debug for InjectedEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InjectedEndpoint")
            .field("id", &self.endpoint.id())
            .finish_non_exhaustive()
    }
}
