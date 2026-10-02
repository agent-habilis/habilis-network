//! The browser backend: chunks in `IndexedDB`, keyed by content.
//!
//! Reachable from the main thread, which is what makes it the browser backend
//! that matters — a tab can seed without spinning up a Worker.
//!
//! Unlike [`FsOrigin`], this **does** copy the bytes in. A browser has no path
//! back to a file the user picked, so a tab that fetched a chunk has nowhere
//! else to keep it. That is a property of the platform rather than a design
//! choice, and it is why the store-versus-source split exists.
//!
//! # One database for every share
//!
//! Chunks live in a single database rather than one per share, because a chunk
//! addressed by content is the same chunk whichever share it arrived through —
//! and keeping them apart would mean fetching the same bytes once per share.
//!
//! That has a consequence worth stating: **the store will happily answer for a
//! chunk it learned about elsewhere.** Deciding whether a given peer is allowed
//! to ask is not this crate's job — it has never heard of a peer — so the caller
//! scopes its answers, and must, or holding a chunk becomes a way for anyone to
//! probe what else you hold.
//!
//! [`FsOrigin`]: crate::FsOrigin

use std::cell::RefCell;
use std::collections::HashSet;

use anyhow::{Context as _, Result, bail};
use js_sys::Uint8Array;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast as _, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{IdbDatabase, IdbFactory, IdbRequest, IdbTransaction, IdbTransactionMode};

use crate::{ChunkHash, ChunkMap, ChunkSource, ChunkStore, Coverage, FileId, Root, chunk_hash};

/// Object store holding one record per chunk, keyed by its address.
const CHUNKS: &str = "chunks";
/// Object store holding leaf rows and the bind table.
const META: &str = "meta";
/// Key prefix for a stored leaf row.
const MAP_PREFIX: &str = "map/";
/// Key for the bind table.
const BINDS_KEY: &str = "binds";

/// JS errors are not `std::error::Error`, so they cannot ride `?` into
/// `anyhow`. Rendering them at the boundary keeps every signature in the crate
/// identical across backends.
fn js_err(context: &str, error: &JsValue) -> anyhow::Error {
    anyhow::anyhow!("{context}: {error:?}")
}

/// The success/error closure pair kept alive for the duration of one await.
type Handlers = Option<(Closure<dyn FnMut()>, Closure<dyn FnMut()>)>;

/// Hook an `IndexedDB` request **now**, and hand back the future for its result.
///
/// The synchronous half of [`done`], split out for callers that issue many
/// requests before awaiting any of them. Both halves of that pattern need the
/// hooking to happen before the first yield:
///
/// - A transaction goes inactive as soon as control returns to the event loop
///   with no request outstanding, so every request has to be *issued* while the
///   caller still holds the thread.
/// - A request that completes before `onsuccess` is attached never fires it, and
///   the await would hang forever.
///
/// An `async fn` does its work on first poll, which is after both deadlines —
/// hence a plain `fn` returning a future.
///
/// The closures are dropped when that future completes rather than `forget`-ed:
/// this runs once per chunk, and leaking a pair per chunk would be a leak
/// proportional to the data transferred.
fn watch(request: &IdbRequest) -> impl Future<Output = Result<JsValue>> + use<> {
    let mut keep: Handlers = None;
    let promise = js_sys::Promise::new(&mut |resolve, reject| {
        let ok_request = request.clone();
        let ok = Closure::<dyn FnMut()>::new(move || {
            let value = ok_request.result().unwrap_or(JsValue::UNDEFINED);
            let _ = resolve.call1(&JsValue::NULL, &value);
        });
        let bad_request = request.clone();
        let bad = Closure::<dyn FnMut()>::new(move || {
            let error = bad_request
                .error()
                .ok()
                .flatten()
                .map_or_else(|| JsValue::from_str("request failed"), JsValue::from);
            let _ = reject.call1(&JsValue::NULL, &error);
        });
        request.set_onsuccess(Some(ok.as_ref().unchecked_ref()));
        request.set_onerror(Some(bad.as_ref().unchecked_ref()));
        keep = Some((ok, bad));
    });
    async move {
        let outcome = JsFuture::from(promise).await;
        drop(keep);
        outcome.map_err(|error| js_err("an IndexedDB request", &error))
    }
}

/// Await an `IndexedDB` request.
async fn done(request: &IdbRequest) -> Result<JsValue> {
    watch(request).await
}

/// Await a transaction's completion.
///
/// Distinct from awaiting the last request in it: a request can succeed and the
/// transaction still abort, and only `oncomplete` means the write is durable.
/// Reporting a chunk as held before that would advertise bytes that never
/// landed — the "peer that lies" failure, from the storage end.
async fn committed(transaction: &IdbTransaction) -> Result<()> {
    let mut keep: Handlers = None;
    let promise = js_sys::Promise::new(&mut |resolve, reject| {
        let ok = Closure::<dyn FnMut()>::new(move || {
            let _ = resolve.call1(&JsValue::NULL, &JsValue::UNDEFINED);
        });
        let bad = Closure::<dyn FnMut()>::new(move || {
            let _ = reject.call1(&JsValue::NULL, &JsValue::from_str("transaction aborted"));
        });
        transaction.set_oncomplete(Some(ok.as_ref().unchecked_ref()));
        transaction.set_onabort(Some(bad.as_ref().unchecked_ref()));
        keep = Some((ok, bad));
    });
    let outcome = JsFuture::from(promise).await;
    drop(keep);
    outcome
        .map(|_| ())
        .map_err(|error| js_err("an IndexedDB transaction", &error))
}

/// Whether either object store this backend needs is absent.
fn missing_stores(db: &IdbDatabase) -> bool {
    let names = db.object_store_names();
    let mut chunks = false;
    let mut meta = false;
    for index in 0..names.length() {
        match names.get(index).as_deref() {
            Some(CHUNKS) => chunks = true,
            Some(META) => meta = true,
            _ => {}
        }
    }
    !(chunks && meta)
}

/// The database's current version, as a `u32`.
fn version_of(db: &IdbDatabase) -> u32 {
    // `version()` is an `unsigned long long` in the IDL and comes back as an
    // `f64`. Clamped rather than cast: a version this store did not write is
    // not worth trusting into an arithmetic that decides a schema upgrade.
    let raw = db.version();
    if raw.is_finite() && (1.0..=f64::from(u32::MAX - 1)).contains(&raw) {
        // Truncation is impossible inside the range checked above.
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "bounded to 1..=u32::MAX-1 immediately above"
        )]
        {
            raw as u32
        }
    } else {
        1
    }
}

/// A content-addressed store backed by `IndexedDB`. Not `Send`.
#[derive(Debug)]
pub struct IdbStore {
    db: IdbDatabase,
    /// Live set for the current reclamation pass, in memory only. A pass that
    /// is interrupted costs a re-mark and nothing else.
    marks: RefCell<Option<HashSet<ChunkHash>>>,
}

impl IdbStore {
    /// Open, creating the database if it is absent.
    ///
    /// # Errors
    /// `IndexedDB` is unreachable — a browser in private mode may refuse it —
    /// or the schema upgrade fails.
    pub async fn open(name: &str) -> Result<Self> {
        let factory: IdbFactory = js_sys::Reflect::get(&js_sys::global(), &"indexedDB".into())
            .map_err(|error| js_err("reaching indexedDB", &error))?
            .dyn_into()
            .map_err(|value| js_err("indexedDB was not a factory", &value))?;

        let request = factory
            .open_with_u32(name, 1)
            .map_err(|error| js_err(&format!("opening database {name}"), &error))?;

        // The schema is created inside `onupgradeneeded`, which fires before
        // `onsuccess`. Registering it after the open request would be too late.
        let upgrade_target = request.clone();
        let upgrade = Closure::<dyn FnMut()>::new(move || {
            let Ok(value) = upgrade_target.result() else {
                return;
            };
            let Ok(db) = value.dyn_into::<IdbDatabase>() else {
                return;
            };
            for store in [META, CHUNKS] {
                // Out-of-line keys: every key is supplied at `put` time rather
                // than read out of the value, because the values are raw bytes
                // with nowhere to put one.
                let _ = db.create_object_store(store);
            }
        });
        request.set_onupgradeneeded(Some(upgrade.as_ref().unchecked_ref()));

        let value = done(request.as_ref()).await?;
        drop(upgrade);
        let db: IdbDatabase = value
            .dyn_into()
            .map_err(|value| js_err("open did not yield a database", &value))?;

        // Self-heal a database that exists at this version but has no stores.
        //
        // Object stores can only be created inside `onupgradeneeded`, which
        // fires only when the version *rises* — so a database left empty at
        // version 1 can never gain them by being opened at version 1 again. It
        // looks healthy and silently refuses every write. Bumping the version
        // is the only way back, and doing it here means a peer poisoned by an
        // earlier build repairs itself on the next visit instead of seeding
        // nothing forever.
        if missing_stores(&db) {
            let next = version_of(&db) + 1;
            db.close();
            return Self::open_at(&factory, name, next).await;
        }

        Ok(Self {
            db,
            marks: RefCell::new(None),
        })
    }

    /// Open at an explicit version, creating whatever stores are absent.
    async fn open_at(factory: &IdbFactory, name: &str, version: u32) -> Result<Self> {
        let request = factory
            .open_with_u32(name, version)
            .map_err(|error| js_err(&format!("reopening database {name}"), &error))?;
        let upgrade_target = request.clone();
        let upgrade = Closure::<dyn FnMut()>::new(move || {
            let Ok(value) = upgrade_target.result() else {
                return;
            };
            let Ok(db) = value.dyn_into::<IdbDatabase>() else {
                return;
            };
            for store in [META, CHUNKS] {
                let _ = db.create_object_store(store);
            }
        });
        request.set_onupgradeneeded(Some(upgrade.as_ref().unchecked_ref()));
        let value = done(request.as_ref()).await?;
        drop(upgrade);
        let db: IdbDatabase = value
            .dyn_into()
            .map_err(|value| js_err("reopen did not yield a database", &value))?;
        if missing_stores(&db) {
            bail!("{name} is missing its object stores even after an upgrade");
        }
        Ok(Self {
            db,
            marks: RefCell::new(None),
        })
    }

    /// Adopt an existing database, **without creating one**.
    ///
    /// Deliberately distinct from [`Self::open`]: merely *browsing* a share must
    /// not leave storage behind, so the read-only paths use this and find
    /// nothing rather than quietly provisioning a database.
    ///
    /// # Why this asks `databases()` first
    ///
    /// `IndexedDB` has no open-if-exists. `open` creates, and it is the *only*
    /// call that can create an object store, because a store can only be made
    /// inside `onupgradeneeded` — which fires only when the version rises.
    ///
    /// So an "adopt" written as a bare `open` at version 1 poisons the very
    /// thing it was trying not to touch: it creates an empty database at
    /// version 1, and the real `open` that follows finds version 1 already
    /// present, never upgrades, and never gets its object stores. Every write
    /// after that fails against a database that looks fine and holds nothing.
    ///
    /// `databases()` is the one way to ask the question without answering it.
    ///
    /// # Errors
    /// `IndexedDB` is unreachable, or the open failed for a reason other than
    /// absence.
    pub async fn adopt(name: &str) -> Result<Option<Self>> {
        let factory: IdbFactory = js_sys::Reflect::get(&js_sys::global(), &"indexedDB".into())
            .map_err(|error| js_err("reaching indexedDB", &error))?
            .dyn_into()
            .map_err(|value| js_err("indexedDB was not a factory", &value))?;

        let listing = js_sys::Reflect::get(&factory, &"databases".into())
            .map_err(|error| js_err("reaching indexedDB.databases", &error))?;
        let Ok(listing) = listing.dyn_into::<js_sys::Function>() else {
            // No `databases()` at all. Refusing is the safe answer: creating one
            // to look inside is exactly the damage this method exists to avoid,
            // and the cost of being wrong is re-fetching rather than corruption.
            return Ok(None);
        };
        let promise = listing
            .call0(&factory)
            .map_err(|error| js_err("listing databases", &error))?;
        let found = JsFuture::from(js_sys::Promise::from(promise))
            .await
            .map_err(|error| js_err("listing databases", &error))?;
        let mut exists = false;
        let entries = js_sys::Array::from(&found);
        for index in 0..entries.length() {
            let entry = entries.get(index);
            if js_sys::Reflect::get(&entry, &"name".into())
                .ok()
                .and_then(|value| value.as_string())
                .is_some_and(|listed| listed == name)
            {
                exists = true;
            }
        }
        if !exists {
            return Ok(None);
        }

        // It exists, so opening cannot create it. Go through `open` so a
        // database left without its stores by an older build still gets them.
        let store = Self::open(name).await?;
        Ok(Some(store))
    }

    fn object_store(
        &self,
        name: &str,
        mode: IdbTransactionMode,
    ) -> Result<(IdbTransaction, web_sys::IdbObjectStore)> {
        let transaction = self
            .db
            .transaction_with_str_and_mode(name, mode)
            .map_err(|error| js_err(&format!("opening a transaction on {name}"), &error))?;
        let store = transaction
            .object_store(name)
            .map_err(|error| js_err(&format!("reaching object store {name}"), &error))?;
        Ok((transaction, store))
    }

    /// Which of `addresses` this store holds, in one transaction.
    ///
    /// `get_key` rather than `get`: the question is presence, and `get` would
    /// pull every chunk's bytes across the boundary — 64 `KiB` a piece — to
    /// answer it. And one transaction rather than one each, because the
    /// per-request overhead is what makes a per-chunk loop slow, not the lookups.
    ///
    /// Every request is issued before any is awaited. That is required twice
    /// over — see [`watch`] — and it is why this collects futures rather than
    /// awaiting in the loop that builds them.
    async fn present(&self, addresses: &[ChunkHash]) -> Result<Vec<bool>> {
        if addresses.is_empty() {
            return Ok(Vec::new());
        }
        let (_transaction, store) = self.object_store(CHUNKS, IdbTransactionMode::Readonly)?;
        let mut pending = Vec::with_capacity(addresses.len());
        for address in addresses {
            let request = store
                .get_key(&JsValue::from_str(&address.to_hex()))
                .map_err(|error| js_err("probing for a chunk", &error))?;
            pending.push(watch(&request));
        }
        let mut held = Vec::with_capacity(pending.len());
        for probe in pending {
            let value = probe.await?;
            held.push(!value.is_undefined() && !value.is_null());
        }
        Ok(held)
    }

    async fn read(&self, name: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let (_transaction, store) = self.object_store(name, IdbTransactionMode::Readonly)?;
        let request = store
            .get(&JsValue::from_str(key))
            .map_err(|error| js_err(&format!("reading {key}"), &error))?;
        let value = done(&request).await?;
        if value.is_undefined() || value.is_null() {
            return Ok(None);
        }
        Ok(Some(Uint8Array::new(&value).to_vec()))
    }

    async fn write(&self, name: &str, key: &str, bytes: &[u8]) -> Result<()> {
        let (transaction, store) = self.object_store(name, IdbTransactionMode::Readwrite)?;
        let value = Uint8Array::from(bytes);
        store
            .put_with_key(value.as_ref(), &JsValue::from_str(key))
            .map_err(|error| js_err(&format!("writing {key}"), &error))?;
        committed(&transaction).await
    }

    async fn erase(&self, name: &str, keys: &[String]) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        let (transaction, store) = self.object_store(name, IdbTransactionMode::Readwrite)?;
        for key in keys {
            store
                .delete(&JsValue::from_str(key))
                .map_err(|error| js_err(&format!("deleting {key}"), &error))?;
        }
        committed(&transaction).await
    }

    /// Every chunk address currently stored. Only the sweep needs this.
    async fn stored_addresses(&self) -> Result<Vec<ChunkHash>> {
        let (_transaction, store) = self.object_store(CHUNKS, IdbTransactionMode::Readonly)?;
        let request = store
            .get_all_keys()
            .map_err(|error| js_err("listing chunk keys", &error))?;
        let value = done(&request).await?;
        let keys = js_sys::Array::from(&value);
        let mut found = Vec::with_capacity(keys.length() as usize);
        for index in 0..keys.length() {
            if let Some(text) = keys.get(index).as_string()
                && let Ok(hash) = ChunkHash::from_hex(&text)
            {
                found.push(hash);
            }
        }
        Ok(found)
    }

    async fn load_binds(&self) -> Vec<(String, u64, i64, Root)> {
        let Ok(Some(bytes)) = self.read(META, BINDS_KEY).await else {
            return Vec::new();
        };
        let text = String::from_utf8_lossy(&bytes);
        let mut binds = Vec::new();
        for line in text.lines() {
            let mut fields = line.split('\t');
            let (Some(key), Some(size), Some(mtime), Some(root)) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            // A malformed row costs that row, not the table: losing one binding
            // re-hashes one file, losing the table re-hashes everything.
            let (Ok(size), Ok(mtime), Ok(root)) = (
                size.parse::<u64>(),
                mtime.parse::<i64>(),
                Root::from_hex(root),
            ) else {
                continue;
            };
            binds.push((key.to_owned(), size, mtime, root));
        }
        binds
    }
}

fn map_key(root: Root) -> String {
    format!("{MAP_PREFIX}{}", root.to_hex())
}

/// Serialize a leaf row: `size(u64 LE) ‖ count(u32 LE) ‖ leaves(32 × count)`.
fn encode_map(map: &ChunkMap) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + map.len() * 32);
    out.extend_from_slice(&map.size().to_le_bytes());
    out.extend_from_slice(&u32::try_from(map.len()).unwrap_or(u32::MAX).to_le_bytes());
    for leaf in map.leaves() {
        out.extend_from_slice(leaf.as_bytes());
    }
    out
}

fn decode_map(bytes: &[u8]) -> Result<ChunkMap> {
    if bytes.len() < 12 {
        bail!(
            "a stored chunk map is at least 12 bytes, got {}",
            bytes.len()
        );
    }
    let size = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
    let count = u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes")) as usize;
    let expected = 12usize
        .checked_add(count.checked_mul(32).context("row length overflows")?)
        .context("row length overflows")?;
    if bytes.len() < expected {
        bail!(
            "a {count}-leaf row needs {expected} bytes, got {}",
            bytes.len()
        );
    }
    let mut leaves = Vec::with_capacity(count);
    for index in 0..count {
        let start = 12 + index * 32;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[start..start + 32]);
        leaves.push(ChunkHash::from_bytes(digest));
    }
    // `from_leaves` recomputes the root, so a row corrupted in storage simply
    // names a different file rather than impersonating this one.
    ChunkMap::from_leaves(leaves, size)
}

impl ChunkSource for IdbStore {
    async fn get(&self, hash: ChunkHash) -> Result<Option<Vec<u8>>> {
        let Some(bytes) = self.read(CHUNKS, &hash.to_hex()).await? else {
            return Ok(None);
        };
        // Verify on the way out as well as on the way in. Storage can rot, and
        // a browser's quota manager is not a filesystem — serving bytes that no
        // longer address what was asked for would make this tab the peer
        // everyone else has to defend against.
        if chunk_hash(&bytes) != hash {
            return Ok(None);
        }
        Ok(Some(bytes))
    }

    async fn has(&self, hash: ChunkHash) -> Result<bool> {
        Ok(self
            .present(&[hash])
            .await?
            .first()
            .copied()
            .unwrap_or(false))
    }

    async fn map(&self, root: Root) -> Result<Option<ChunkMap>> {
        let Some(bytes) = self.read(META, &map_key(root)).await? else {
            return Ok(None);
        };
        Ok(Some(decode_map(&bytes)?))
    }

    /// Probes this root's leaves, and scans nothing.
    ///
    /// The store is global across every share this peer has touched, so asking
    /// it to enumerate itself to answer for one file costs the whole keyspace to
    /// learn about a handful of chunks. Probing costs the file.
    ///
    /// [`Self::coverage_of`] takes the opposite route, and the two are not in
    /// disagreement: see the note there.
    async fn coverage(&self, root: Root) -> Result<Coverage> {
        let Some(map) = self.map(root).await? else {
            return Ok(Coverage::empty(0));
        };
        let held = self.present(map.leaves()).await?;
        let mut coverage = Coverage::empty(map.len());
        for (index, present) in held.iter().enumerate() {
            if *present {
                coverage.insert(index);
            }
        }
        Ok(coverage)
    }

    /// Enumerates the keyspace once, and probes nothing.
    ///
    /// The inverse of [`Self::coverage`]'s trade, and deliberately: a caller
    /// asking about every root it knows is asking about most of what it stores,
    /// so one enumeration answers all of them at a cost the per-root probes
    /// would pay again for each. The default loop on the trait would re-scan the
    /// store per root, which is the quadratic this method exists to remove.
    ///
    /// A root with no stored map covers nothing, and holds its place in the
    /// answer — callers zip these back onto what they asked about.
    async fn coverage_of(&self, roots: &[Root]) -> Result<Vec<Coverage>> {
        if roots.is_empty() {
            return Ok(Vec::new());
        }
        let held: HashSet<ChunkHash> = self.stored_addresses().await?.into_iter().collect();
        let mut out = Vec::with_capacity(roots.len());
        for root in roots {
            let Some(map) = self.map(*root).await? else {
                out.push(Coverage::empty(0));
                continue;
            };
            let mut coverage = Coverage::empty(map.len());
            for (index, leaf) in map.leaves().iter().enumerate() {
                if held.contains(leaf) {
                    coverage.insert(index);
                }
            }
            out.push(coverage);
        }
        Ok(out)
    }

    async fn bind(&self, file: &FileId) -> Result<Option<Root>> {
        for (key, size, mtime, root) in self.load_binds().await {
            if key == file.key {
                if size != file.size || mtime != file.mtime {
                    return Ok(None);
                }
                return Ok(Some(root));
            }
        }
        Ok(None)
    }
}

impl ChunkStore for IdbStore {
    async fn put(&self, hash: ChunkHash, bytes: &[u8]) -> Result<()> {
        let actual = chunk_hash(bytes);
        if actual != hash {
            bail!("these bytes address {actual}, not {hash}");
        }
        self.write(CHUNKS, &hash.to_hex(), bytes).await
    }

    async fn put_map(&self, map: &ChunkMap) -> Result<()> {
        self.write(META, &map_key(map.root()), &encode_map(map))
            .await
    }

    async fn set_bind(&self, file: &FileId, root: Root) -> Result<()> {
        let mut binds = self.load_binds().await;
        binds.retain(|(key, _, _, _)| key != &file.key);
        binds.push((file.key.clone(), file.size, file.mtime, root));
        let mut text = String::new();
        for (key, size, mtime, bound) in &binds {
            use std::fmt::Write as _;
            let _ = writeln!(text, "{key}\t{size}\t{mtime}\t{}", bound.to_hex());
        }
        self.write(META, BINDS_KEY, text.as_bytes()).await
    }

    async fn start_marking(&self) -> Result<()> {
        *self.marks.borrow_mut() = Some(HashSet::new());
        Ok(())
    }

    async fn mark(&self, root: Root) -> Result<()> {
        let map = self.map(root).await?.context(
            "cannot mark a root with no stored chunk map — derive the live set \
             from persisted maps, never from an in-memory held-set",
        )?;
        let mut marks = self.marks.borrow_mut();
        marks
            .get_or_insert_with(HashSet::new)
            .extend(map.leaves().iter().copied());
        Ok(())
    }

    async fn sweep(&self) -> Result<u64> {
        let live = self.marks.borrow_mut().take().unwrap_or_default();
        let doomed: Vec<String> = self
            .stored_addresses()
            .await?
            .into_iter()
            .filter(|hash| !live.contains(hash))
            .map(|hash| hash.to_hex())
            .collect();
        let count = u64::try_from(doomed.len()).unwrap_or(u64::MAX);
        self.erase(CHUNKS, &doomed).await?;
        Ok(count)
    }

    async fn clear(&self, hashes: &[ChunkHash]) -> Result<()> {
        let keys: Vec<String> = hashes.iter().map(ChunkHash::to_hex).collect();
        self.erase(CHUNKS, &keys).await
    }
}
