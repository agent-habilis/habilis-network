//! Members of one loopback room must become one mesh, however they start.
//!
//! A loopback room has no lookup. Its members meet on a ladder of local ports, and the
//! member that holds the beacon is on the first rung it could bind. Issue #4: such a room
//! split into meshes that never found each other.
//!
//! - **A**: a creator and five joiners, two seconds apart. The flow of a person at a
//!   terminal, and the baseline.
//! - **B**: the beacon holder leaves after every member released the rendezvous, then two
//!   joiners arrive by id.
//! - **C**: the creator leaves at once, two joiners start together, and the rung probe of
//!   both reads silence (`Request::BlindRungProbes`). One of them binds the first rung. The
//!   other stays a peer of it: silence does not bind a second rung. Two joiners follow, one by
//!   one.
//! - **D**: two released holders, with no IP block. Case E's setup gives a room of five old
//!   members that hold their claims back, and a new holder with four joiners of its own, both
//!   sides released. Then one old member, with three links or more, reads its rung probe as
//!   "not ours" and binds the next rung: a holder on a higher rung, with two meshes that share
//!   no link. The engine must merge them by itself.
//! - **F**: D, and the holder on the higher rung sheds its beacon (`Request::ShedBeacon`)
//!   instead of waiting for the engine to do it. The merge then needs only that a member that
//!   reads a holder of another mesh goes to it.
//!
//! - **E**: the one-by-one path. The creator leaves while five old members, each with three
//!   links or more, hold their claims back (`Request::HoldClaims`). A joiner starts and takes
//!   the free rung. The old members then find the rung "ours" on their walk, want no
//!   rendezvous (they have three links or more), and graft nothing. A later joiner lands on
//!   the new holder.
//!
//! - **G**: the shape of a field report. A room that ran for a while: the creator and eleven
//!   joiners one by one, every one of them released. Then four joiners start at the same
//!   instant, as one agent spawns them. G1 keeps the creator, G2 lets it leave first. No hook:
//!   G shows what the engine does by itself.
//!
//! The probe is blind for a member, not for the process: a process-wide dial would make
//! every in-process member misread at once, which is not what a loaded host does.
//!
//! Own integration binary: `Tuning` is a process-wide `OnceLock`, and this file shortens
//! the heal tick and the co-host grace to seconds. Every test is `#[ignore]`: a round
//! stands up several real members, and the rounds take turns.

#![cfg(all(feature = "host", feature = "iroh-test-utils"))]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use habilis_network::membership::{self, Membership, Request};
use habilis_network::runtime::tuning::{Tuning, init};
use tokio::sync::mpsc::UnboundedReceiver;

/// The gap between two joiners of the one-by-one flow.
const SPACING: Duration = Duration::from_secs(2);

/// How long the creator may take to bind the first rung.
const BEACON_DEADLINE: Duration = Duration::from_secs(30);

/// How long the members may take to see each other, from the last start. A mesh that
/// heals needs a few heal ticks and one round of anti-entropy, so the bound is generous.
const MERGE_DEADLINE: Duration = Duration::from_secs(90);

/// How long the old members of B may take to release the rendezvous.
const RELEASE_DEADLINE: Duration = Duration::from_secs(90);

/// The links at which a member lets the rendezvous go (`RENDEZVOUS_RELEASE_LINKS`).
const RELEASE_LINKS: usize = 3;

/// Tests of this file take turns: they share the log of the round and the loopback ports.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The file that the log of the running round goes to.
static ROUND_LOG: Mutex<Option<std::fs::File>> = Mutex::new(None);

struct RoundLogWriter;

impl std::io::Write for RoundLogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if let Some(file) = ROUND_LOG.lock().expect("no poison").as_mut() {
            file.write_all(bytes)?;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// One global subscriber that writes to the file of the running round. A per-round
/// `set_default` would lose the events of the worker threads.
fn init_process() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        init(Tuning {
            heal_interval_secs: 3,
            cohost_grace_secs: 2,
            ..Tuning::DEFAULTS
        });
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("habilis_network=info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(|| RoundLogWriter)
            .with_ansi(false)
            .try_init();
    });
}

/// One round: its log, kept when the round fails. `HABILIS_TEST_LOG_DUMP` names the prefix
/// of the file (the temp directory if it is not set).
struct Round {
    name: &'static str,
    path: PathBuf,
}

impl Round {
    fn begin(name: &'static str) -> Self {
        init_process();
        let prefix = std::env::var("HABILIS_TEST_LOG_DUMP").unwrap_or_else(|_| {
            std::env::temp_dir()
                .join("loopback-room-split")
                .display()
                .to_string()
        });
        let path: PathBuf = format!("{prefix}.{name}.{}", std::process::id()).into();
        *ROUND_LOG.lock().expect("no poison") =
            Some(std::fs::File::create(&path).expect("create the log file of the round"));
        Self { name, path }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.path).unwrap_or_default()
    }

    /// The `(node, port)` of every beacon that was bound on a rung, in order.
    fn beacons(&self) -> Vec<(String, String)> {
        self.log()
            .lines()
            .filter(|line| line.contains("beacon assumed: bound rendezvous ladder rung"))
            .map(|line| (field(line, "node="), field(line, "port=")))
            .collect()
    }

    /// How many times the member with the short id `node` read a lower rung that answered as the
    /// beacon of its mesh: each one is a shed of its beacon.
    fn lower_rung_answers_of(&self, node: &str) -> usize {
        self.log()
            .lines()
            .filter(|line| line.contains("a lower rung answers as the beacon of our mesh"))
            .filter(|line| field(line, "node=") == node)
            .count()
    }

    /// The ports that the members with the short ids `nodes` bound a beacon on.
    fn ports_bound_by(&self, nodes: &[String]) -> BTreeSet<String> {
        self.beacons()
            .into_iter()
            .filter(|(node, _)| nodes.contains(node))
            .map(|(_, port)| port)
            .collect()
    }

    /// Whether the member with the short id `node` bound a rung.
    fn has_bound_a_rung(&self, node: &str) -> bool {
        self.beacons().iter().any(|(bound, _)| bound == node)
    }

    /// How many different members logged a release with `RELEASE_LINKS` links or more.
    fn members_released_with_enough_links(&self) -> usize {
        self.log()
            .lines()
            .filter(|line| line.contains("released the rendezvous"))
            .filter(|line| {
                field(line, "links=")
                    .parse::<usize>()
                    .is_ok_and(|count| count >= RELEASE_LINKS)
            })
            .map(|line| field(line, "local="))
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// Print the line of the round and end it. A round that failed panics and keeps its log.
    fn conclude(self, verdict: Result<Duration, String>) {
        let beacons = self.beacons();
        *ROUND_LOG.lock().expect("no poison") = None;
        match verdict {
            Ok(time) => {
                eprintln!(
                    "ROUND {} converged after {time:?}, beacons bound {beacons:?}",
                    self.name
                );
                // A green round that nobody can read gives no reason why it is green.
                if std::env::var_os("HABILIS_TEST_KEEP_LOG").is_some() {
                    eprintln!("ROUND {} log kept in {}", self.name, self.path.display());
                } else {
                    let _ = std::fs::remove_file(&self.path);
                }
            }
            Err(text) => panic!(
                "ROUND {} split: {text}; beacons bound {beacons:?}; the log of the round is in {}",
                self.name,
                self.path.display()
            ),
        }
    }
}

/// The value of `key` (like `port=`) in a log line, up to the next space.
fn field(line: &str, key: &str) -> String {
    line.split(key)
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_default()
        .to_owned()
}

struct Member {
    membership: Membership,
    _events: UnboundedReceiver<String>,
}

impl Member {
    /// A creator when `mesh` is `None`, a joiner by id otherwise. No lookup: a loopback room.
    async fn open(nick: &str, mesh: Option<&str>) -> Self {
        let (sink, events) = membership::json_sink();
        let membership = membership::join(
            &membership::Opts {
                nick: Some(nick.to_owned()),
                mesh: mesh.map(str::to_owned),
                ..membership::Opts::default()
            },
            sink,
        )
        .await
        .expect("open a member");
        Self {
            membership,
            _events: events,
        }
    }

    fn mesh_id(&self) -> String {
        self.membership.node.mesh_id().to_string()
    }

    /// The live peers in the roster of this member.
    async fn peers(&self) -> usize {
        let json = self
            .membership
            .request(|reply| Request::Peers { reply })
            .await
            .unwrap_or_default();
        serde_json::from_str::<serde_json::Value>(&json)
            .ok()
            .and_then(|roster| {
                roster["peers"].as_array().map(|peers| {
                    peers
                        .iter()
                        .filter(|peer| peer["quiet"] != serde_json::Value::Bool(true))
                        .count()
                })
            })
            .unwrap_or(0)
    }

    /// The short id that the beacon lines of the log name this member by.
    fn short_id(&self) -> String {
        self.membership.node.endpoint_id().fmt_short().to_string()
    }

    async fn stall_beacon(&self) {
        self.membership
            .request(|reply| Request::StallBeacon { reply })
            .await
            .expect("the loop answers");
    }

    async fn shed_beacon(&self) {
        self.membership
            .request(|reply| Request::ShedBeacon { reply })
            .await
            .expect("the loop answers");
    }

    async fn hold_claims(&self, hold: bool) {
        self.membership
            .request(|reply| Request::HoldClaims { hold, reply })
            .await
            .expect("the loop answers");
    }

    async fn blind_rung_probes(&self) {
        self.set_blind_rung_probes(true).await;
    }

    /// The reading of the host is true again. The false reading of a loaded host is a moment, not
    /// a state of the member: a hook that stayed would make a holder that sheds read "foreign"
    /// again at its next walk and bind the same rung again, which no host does for long.
    async fn unblind_rung_probes(&self) {
        self.set_blind_rung_probes(false).await;
    }

    async fn set_blind_rung_probes(&self, blind: bool) {
        self.membership
            .request(|reply| Request::BlindRungProbes { blind, reply })
            .await
            .expect("the loop answers");
    }

    async fn leave(self) {
        let _ = self.membership.node.leave().await;
    }
}

/// Wait until every member counts every other member, or say what each one counted.
async fn become_one_mesh(members: &[&Member], deadline: Duration) -> Result<Duration, String> {
    let started = Instant::now();
    let expected = members.len() - 1;
    loop {
        let mut counts = Vec::new();
        for member in members {
            counts.push(member.peers().await);
        }
        if counts.iter().all(|count| *count == expected) {
            return Ok(started.elapsed());
        }
        if started.elapsed() >= deadline {
            return Err(format!(
                "{} members did not see each other inside {deadline:?}: each counts {counts:?} peers, the roster is {expected}",
                members.len()
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn wait_for_beacons(round: &Round, count: usize) -> Result<(), String> {
    let started = Instant::now();
    while round.beacons().len() < count {
        if started.elapsed() >= BEACON_DEADLINE {
            return Err(format!(
                "no beacon was bound on a rung inside {BEACON_DEADLINE:?}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Ok(())
}

async fn wait_for_rung_of(round: &Round, node: &str) -> Result<(), String> {
    let started = Instant::now();
    while !round.has_bound_a_rung(node) {
        if started.elapsed() >= BEACON_DEADLINE {
            return Err(format!(
                "precondition: member {node} bound no rung inside {BEACON_DEADLINE:?}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Ok(())
}

/// The members `nodes` must hold beacons on two different rungs: a round whose second beacon
/// shared the rung of the first would not have run the path that the case is about.
fn two_distinct_rungs(round: &Round, nodes: &[String]) -> Result<(), String> {
    let ports = round.ports_bound_by(nodes);
    if ports.len() < 2 {
        return Err(format!(
            "the blind path did not run: one rung only, {ports:?} for {nodes:?}"
        ));
    }
    Ok(())
}

async fn wait_for_releases(round: &Round, count: usize) -> Result<(), String> {
    let started = Instant::now();
    while round.members_released_with_enough_links() < count {
        if started.elapsed() >= RELEASE_DEADLINE {
            return Err(format!(
                "precondition: {} of {count} members released the rendezvous with {RELEASE_LINKS} links or more inside {RELEASE_DEADLINE:?}",
                round.members_released_with_enough_links()
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Ok(())
}

async fn open_joiners(members: &mut Vec<Member>, mesh: &str, names: &[String]) {
    for nick in names {
        tokio::time::sleep(SPACING).await;
        members.push(Member::open(nick, Some(mesh)).await);
    }
}

fn nicks(prefix: &str, count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("{prefix}-{index:02}"))
        .collect()
}

/// A creator, then `joiners` joiners one by one. Every member must see every other.
async fn one_by_one(
    round: &Round,
    members: &mut Vec<Member>,
    joiners: usize,
) -> Result<Duration, String> {
    members.push(Member::open("creator", None).await);
    wait_for_beacons(round, 1).await?;
    let mesh = members[0].mesh_id();
    open_joiners(members, &mesh, &nicks("joiner", joiners)).await;
    let all: Vec<&Member> = members.iter().collect();
    become_one_mesh(&all, MERGE_DEADLINE).await
}

/// The creator and five joiners form a mesh and release the rendezvous. Then the beacon
/// holder leaves, and two joiners arrive by id.
async fn late_joiners_after_the_holder_left(
    round: &Round,
    members: &mut Vec<Member>,
) -> Result<Duration, String> {
    one_by_one(round, members, 5).await?;
    wait_for_releases(round, 5).await?;
    let creator = members.remove(0);
    let mesh = creator.mesh_id();
    creator.leave().await;
    open_joiners(members, &mesh, &nicks("late", 2)).await;
    let all: Vec<&Member> = members.iter().collect();
    become_one_mesh(&all, MERGE_DEADLINE).await
}

/// The old members hold their claims back, the creator leaves, and one joiner starts and takes
/// the free rung. Then the holds go, and one more joiner comes. Every member must see every
/// other.
async fn late_joiner_claims_before_the_old_members(
    round: &Round,
    members: &mut Vec<Member>,
) -> Result<Duration, String> {
    one_by_one(round, members, 5).await?;
    wait_for_releases(round, 5).await?;
    for member in members.iter() {
        member.hold_claims(true).await;
    }
    let creator = members.remove(0);
    let mesh = creator.mesh_id();
    creator.leave().await;

    let first = Member::open("late-first", Some(&mesh)).await;
    let first_id = first.short_id();
    members.push(first);
    wait_for_rung_of(round, &first_id).await?;
    for member in members.iter() {
        member.hold_claims(false).await;
    }
    open_joiners(members, &mesh, &nicks("late-after", 1)).await;
    let all: Vec<&Member> = members.iter().collect();
    become_one_mesh(&all, MERGE_DEADLINE).await
}

/// A room that ran for a while: the creator and eleven joiners one by one, every joiner has
/// released the rendezvous. Then four joiners start at the same instant, with no stagger and no
/// hook. The creator leaves first when `creator_leaves` is set. Every member must see every
/// other.
async fn four_joiners_together_after_a_long_run(
    round: &Round,
    members: &mut Vec<Member>,
    creator_leaves: bool,
) -> Result<Duration, String> {
    one_by_one(round, members, 11).await?;
    wait_for_releases(round, 11).await?;
    let mesh = members[0].mesh_id();
    if creator_leaves {
        members.remove(0).leave().await;
    }
    let names = nicks("burst", 4);
    let opened = futures_util::future::join_all(
        names
            .iter()
            .map(|nick| Member::open(nick, Some(mesh.as_str()))),
    )
    .await;
    members.extend(opened);
    let all: Vec<&Member> = members.iter().collect();
    become_one_mesh(&all, MERGE_DEADLINE).await
}

/// Two meshes of one room, each with a holder, and every member released: E's setup, then one
/// old member that binds the next rung because its probe reads "not ours". The old members hold
/// their claims back but that one, so that the only second holder is the one that the test
/// names. The member at index 0 is the holder on the higher rung when this returns.
async fn two_released_holders(round: &Round, members: &mut Vec<Member>) -> Result<(), String> {
    one_by_one(round, members, 5).await?;
    wait_for_releases(round, 5).await?;
    for member in members.iter() {
        member.hold_claims(true).await;
    }
    let creator = members.remove(0);
    let mesh = creator.mesh_id();
    creator.leave().await;

    let first = Member::open("late-first", Some(&mesh)).await;
    let first_id = first.short_id();
    members.push(first);
    wait_for_rung_of(round, &first_id).await?;
    open_joiners(members, &mesh, &nicks("late-after", 4)).await;
    // The five old members, and the new holder with four joiners that released: nine releases.
    wait_for_releases(round, 9).await?;
    let old = members[0].peers().await;
    let new = members[members.len() - 1].peers().await;
    if old != 4 || new != 4 {
        return Err(format!(
            "precondition: the two meshes are not apart, an old member counts {old} peers and a new one {new}, each should count 4"
        ));
    }

    let second = &members[0];
    second.blind_rung_probes().await;
    second.hold_claims(false).await;
    wait_for_rung_of(round, &second.short_id()).await?;
    two_distinct_rungs(round, &[first_id, second.short_id()])?;
    second.unblind_rung_probes().await;
    Ok(())
}

/// Makes every member that is opened while it lives blind from the first probe of its startup
/// walk, and ends that when it drops: a panic in an open must not leave every later case blind.
struct BlindNewMembers;

impl BlindNewMembers {
    fn on() -> Self {
        membership::blind_new_members(true);
        Self
    }
}

impl Drop for BlindNewMembers {
    fn drop(&mut self) {
        membership::blind_new_members(false);
    }
}

/// Open the starters together, each blind from its first probe. A hook that is set after the
/// open comes after a walk that read the truth, and that walk is the one that the cases are about.
async fn open_starters_blind(names: &[String], mesh: &str) -> Vec<Member> {
    let _blind = BlindNewMembers::on();
    futures_util::future::join_all(names.iter().map(|nick| Member::open(nick, Some(mesh)))).await
}

/// The creator mints the room and leaves, so that no beacon holds a rung. `starters`
/// joiners start together and every one of them reads its rung probe as silence. One of them
/// binds the first rung and the others stay its peers. Then `late` joiners come one by one.
/// Every member must see every other, and no starter binds a second rung.
async fn blind_starters(
    round: &Round,
    members: &mut Vec<Member>,
    starters: usize,
    late: usize,
) -> Result<Duration, String> {
    let creator = Member::open("creator", None).await;
    wait_for_beacons(round, 1).await?;
    let mesh = creator.mesh_id();
    creator.leave().await;

    let names = nicks("starter", starters);
    let opened = open_starters_blind(&names, &mesh).await;
    // The creator, and the one starter that took rung 0.
    wait_for_beacons(round, 2).await?;
    for member in &opened {
        member.unblind_rung_probes().await;
    }
    members.extend(opened);
    open_joiners(members, &mesh, &nicks("late", late)).await;
    let all: Vec<&Member> = members.iter().collect();
    let merged = become_one_mesh(&all, MERGE_DEADLINE).await?;
    let bound = round.beacons().len();
    if bound != 2 {
        return Err(format!(
            "the mesh merged after {merged:?}, but {bound} beacons were bound: the creator's and more rungs than the room needs"
        ));
    }
    Ok(merged)
}

/// Case C with the blind hook left on, the form of a host that stays slow: the second starter
/// reads its rung probe as silence at every walk. It must stay a peer of the first starter and
/// merge, bind no second rung and shed nothing.
async fn starters_that_stay_blind(
    round: &Round,
    members: &mut Vec<Member>,
) -> Result<Duration, String> {
    let creator = Member::open("creator", None).await;
    wait_for_beacons(round, 1).await?;
    let mesh = creator.mesh_id();
    creator.leave().await;

    let names = nicks("starter", 2);
    let opened = open_starters_blind(&names, &mesh).await;
    // The creator, and the one starter that took rung 0.
    wait_for_beacons(round, 2).await?;
    let ids: Vec<String> = opened.iter().map(Member::short_id).collect();
    members.extend(opened);
    open_joiners(members, &mesh, &nicks("late", 2)).await;
    let all: Vec<&Member> = members.iter().collect();
    let merged = become_one_mesh(&all, MERGE_DEADLINE).await?;
    let sheds: usize = ids
        .iter()
        .map(|node| round.lower_rung_answers_of(node))
        .sum();
    if sheds > 0 {
        return Err(format!(
            "the mesh merged after {merged:?}, but the blind starters shed their beacon {sheds} times"
        ));
    }
    let bound = round.beacons().len();
    if bound != 2 {
        return Err(format!(
            "the mesh merged after {merged:?}, but {bound} beacons were bound: the creator's and more rungs than the room needs"
        ));
    }
    Ok(merged)
}

/// A start burst on a host that answers late: the room has no holder, two joiners start
/// together and read every rung probe as silence for 3 s, which is less than the 6 s that a
/// rung must stay silent to be bound. Then the host answers. No second rung may be bound, and
/// the room is one mesh. A walk that reads the silence of a loaded host as foreign binds the next
/// rung at the first walk, and the room has two beacons that no probe could tell apart.
async fn start_burst_on_a_host_that_answers_late(
    round: &Round,
    members: &mut Vec<Member>,
) -> Result<Duration, String> {
    let creator = Member::open("creator", None).await;
    wait_for_beacons(round, 1).await?;
    let mesh = creator.mesh_id();
    creator.leave().await;

    let names = nicks("starter", 2);
    let opened = open_starters_blind(&names, &mesh).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    for member in &opened {
        member.unblind_rung_probes().await;
    }
    members.extend(opened);
    open_joiners(members, &mesh, &nicks("late", 2)).await;
    let all: Vec<&Member> = members.iter().collect();
    let merged = become_one_mesh(&all, MERGE_DEADLINE).await?;
    let bound = round.beacons().len();
    if bound != 2 {
        return Err(format!(
            "the mesh merged after {merged:?}, but {bound} beacons were bound: the creator's and one more rung than the room needs"
        ));
    }
    Ok(merged)
}

/// The holder of the beacon stops answering and keeps its rung: a stopped process, a wedged
/// accept loop. Nobody else claims, because the rung is taken, and the members that joined
/// through it hold other links. A joiner that comes later must still find a beacon: the holder
/// has to notice, shed, and serve again.
async fn holder_whose_beacon_stops_answering(
    round: &Round,
    members: &mut Vec<Member>,
) -> Result<Duration, String> {
    one_by_one(round, members, 2).await?;
    let bound = round.beacons().len();
    members[0].stall_beacon().await;
    let started = Instant::now();
    while round.beacons().len() <= bound {
        if started.elapsed() >= Duration::from_secs(45) {
            return Err(
                "no beacon was bound again inside 45 s after the holder of the rung stopped answering"
                    .to_owned(),
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let mesh = members[0].mesh_id();
    open_joiners(members, &mesh, &nicks("late", 1)).await;
    let all: Vec<&Member> = members.iter().collect();
    become_one_mesh(&all, MERGE_DEADLINE).await
}

async fn finish(round: Round, members: Vec<Member>, verdict: Result<Duration, String>) {
    for member in members {
        member.leave().await;
    }
    round.conclude(verdict);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by cargo task matrix"]
async fn joiners_one_by_one_become_one_mesh() {
    let _serial = SERIAL.lock().await;
    let round = Round::begin("one-by-one");
    let mut members = Vec::new();
    let verdict = one_by_one(&round, &mut members, 5).await;
    finish(round, members, verdict).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by cargo task matrix"]
async fn joiners_after_the_beacon_holder_left_meet_the_old_members() {
    let _serial = SERIAL.lock().await;
    let round = Round::begin("after-the-holder");
    let mut members = Vec::new();
    let verdict = late_joiners_after_the_holder_left(&round, &mut members).await;
    finish(round, members, verdict).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by cargo task matrix"]
async fn two_starters_that_read_their_rung_as_silent_join_one_mesh() {
    let _serial = SERIAL.lock().await;
    let round = Round::begin("two-blind-starters");
    let mut members = Vec::new();
    let verdict = blind_starters(&round, &mut members, 2, 2).await;
    finish(round, members, verdict).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by cargo task matrix"]
async fn a_holder_on_a_higher_rung_with_links_enough_joins_the_lower_holder() {
    let _serial = SERIAL.lock().await;
    let round = Round::begin("higher-holder");
    let mut members = Vec::new();
    let verdict = match two_released_holders(&round, &mut members).await {
        Ok(()) => {
            let all: Vec<&Member> = members.iter().collect();
            become_one_mesh(&all, MERGE_DEADLINE).await
        }
        Err(text) => Err(text),
    };
    finish(round, members, verdict).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by cargo task matrix"]
async fn a_holder_with_links_enough_that_shed_its_beacon_joins_the_other_holder() {
    let _serial = SERIAL.lock().await;
    let round = Round::begin("shed-holder");
    let mut members = Vec::new();
    let verdict = match two_released_holders(&round, &mut members).await {
        Ok(()) => {
            members[0].shed_beacon().await;
            let all: Vec<&Member> = members.iter().collect();
            become_one_mesh(&all, MERGE_DEADLINE).await
        }
        Err(text) => Err(text),
    };
    finish(round, members, verdict).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by cargo task matrix"]
async fn a_joiner_that_took_the_free_rung_first_is_met_by_the_old_members() {
    let _serial = SERIAL.lock().await;
    let round = Round::begin("joiner-claims-first");
    let mut members = Vec::new();
    let verdict = late_joiner_claims_before_the_old_members(&round, &mut members).await;
    finish(round, members, verdict).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by cargo task matrix"]
async fn four_joiners_started_together_meet_a_long_running_room_with_its_creator() {
    let _serial = SERIAL.lock().await;
    let round = Round::begin("burst-creator-stays");
    let mut members = Vec::new();
    let verdict = four_joiners_together_after_a_long_run(&round, &mut members, false).await;
    finish(round, members, verdict).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by cargo task matrix"]
async fn four_joiners_started_together_meet_a_long_running_room_after_its_creator_left() {
    let _serial = SERIAL.lock().await;
    let round = Round::begin("burst-creator-left");
    let mut members = Vec::new();
    let verdict = four_joiners_together_after_a_long_run(&round, &mut members, true).await;
    finish(round, members, verdict).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by cargo task matrix"]
async fn two_starters_that_stay_blind_bind_one_rung_and_become_one_mesh() {
    let _serial = SERIAL.lock().await;
    let round = Round::begin("two-blind-starters-persistent");
    let mut members = Vec::new();
    let verdict = starters_that_stay_blind(&round, &mut members).await;
    finish(round, members, verdict).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by cargo task matrix"]
async fn a_start_burst_on_a_host_that_answers_late_binds_no_second_rung() {
    let _serial = SERIAL.lock().await;
    let round = Round::begin("burst-answers-late");
    let mut members = Vec::new();
    let verdict = start_burst_on_a_host_that_answers_late(&round, &mut members).await;
    finish(round, members, verdict).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by cargo task matrix"]
async fn a_holder_whose_beacon_stops_answering_serves_again_and_a_joiner_finds_it() {
    let _serial = SERIAL.lock().await;
    let round = Round::begin("holder-stalled");
    let mut members = Vec::new();
    let verdict = holder_whose_beacon_stops_answering(&round, &mut members).await;
    finish(round, members, verdict).await;
}
