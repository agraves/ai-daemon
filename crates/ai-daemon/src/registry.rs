//! The model registry (§6): one copy of the weights, many callers.
//!
//! ```text
//! /var/lib/ai-daemon/models/
//!   blobs/sha256/<hex>        the weights, named by what they are
//!   manifests/<name>.json     the human name, pointing at a digest
//!   aliases.json              default / fast / embed
//!   staging/                  where ai-daemon-fetch may write, and only there
//! ```
//!
//! Content addressing is not tidiness. It is what makes "two apps asked for
//! `llama-3.1-8b-q4`" resolve to one file, one mmap and one page cache
//! footprint instead of two 5 GB downloads — the entire argument for the
//! daemon owning models rather than each app owning its own.
//!
//! A user's own store under `~/.local/share/ai-daemon/models/` resolves first
//! for that user's sessions, so trying a model does not require root and does
//! not let one user's choice leak into another's.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use ai_daemon_proto::manifest::Manifest;
use sha2::{Digest, Sha256};

use crate::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Store {
    System,
    User,
}

#[derive(Debug, Clone)]
pub struct Resolved {
    pub manifest: Manifest,
    pub blob: PathBuf,
    pub store: Store,
}

pub struct Registry {
    system_root: PathBuf,
    /// Config-level aliases, which a user store may shadow but a client may not.
    config_aliases: BTreeMap<String, String>,
    cache: RwLock<Option<Vec<Manifest>>>,
}

impl Registry {
    pub fn new(state_dir: &Path, config_aliases: BTreeMap<String, String>) -> Registry {
        let system_root = state_dir.join("models");
        for sub in ["blobs/sha256", "manifests", "staging"] {
            let _ = std::fs::create_dir_all(system_root.join(sub));
        }
        Registry { system_root, config_aliases, cache: RwLock::new(None) }
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.system_root.join("staging")
    }

    /// A user's store. Read-only from the daemon's point of view — the daemon
    /// runs as `ai-daemon` and has no business writing into a home directory,
    /// so a user installs there with `aidctl --user`, under their own uid.
    fn user_root(uid: u32) -> Option<PathBuf> {
        let home = home_of_uid(uid)?;
        Some(home.join(".local/share/ai-daemon/models"))
    }

    pub fn invalidate(&self) {
        *self.cache.write().unwrap() = None;
    }

    /// Every model visible to `uid`, user store shadowing system by name.
    pub fn list(&self, uid: Option<u32>) -> Vec<(Manifest, Store)> {
        let mut by_name: BTreeMap<String, (Manifest, Store)> = BTreeMap::new();
        for manifest in self.system_manifests() {
            by_name.insert(manifest.name.clone(), (manifest, Store::System));
        }
        if let Some(root) = uid.and_then(Registry::user_root) {
            for manifest in read_manifests(&root.join("manifests")) {
                by_name.insert(manifest.name.clone(), (manifest, Store::User));
            }
        }
        by_name.into_values().collect()
    }

    fn system_manifests(&self) -> Vec<Manifest> {
        if let Some(cached) = self.cache.read().unwrap().as_ref() {
            return cached.clone();
        }
        let manifests = read_manifests(&self.system_root.join("manifests"));
        *self.cache.write().unwrap() = Some(manifests.clone());
        manifests
    }

    /// Turn an alias or a name into a concrete model. One hop only: an alias
    /// may name a model, never another alias, because a chain of aliases is a
    /// chain nobody can audit.
    pub fn resolve(&self, name: &str, uid: Option<u32>) -> Result<Resolved, String> {
        let target = self.resolve_alias(name, uid).unwrap_or_else(|| name.to_string());

        if let Some(root) = uid.and_then(Registry::user_root) {
            if let Some(manifest) = read_manifest(&root.join("manifests").join(format!("{target}.json"))) {
                let blob = blob_for(&root, &manifest)?;
                return Ok(Resolved { manifest, blob, store: Store::User });
            }
        }
        let path = self.system_root.join("manifests").join(format!("{target}.json"));
        let manifest = read_manifest(&path)
            .ok_or_else(|| format!("no model named {target:?} in this install"))?;
        let blob = blob_for(&self.system_root, &manifest)?;
        Ok(Resolved { manifest, blob, store: Store::System })
    }

    pub fn resolve_alias(&self, alias: &str, uid: Option<u32>) -> Option<String> {
        if let Some(root) = uid.and_then(Registry::user_root) {
            if let Some(target) = read_aliases(&root.join("aliases.json")).remove(alias) {
                return Some(target);
            }
        }
        if let Some(target) = self.config_aliases.get(alias) {
            return Some(target.clone());
        }
        read_aliases(&self.system_root.join("aliases.json")).remove(alias)
    }

    pub fn aliases(&self, uid: Option<u32>) -> BTreeMap<String, String> {
        let mut all = read_aliases(&self.system_root.join("aliases.json"));
        all.extend(self.config_aliases.clone());
        if let Some(root) = uid.and_then(Registry::user_root) {
            all.extend(read_aliases(&root.join("aliases.json")));
        }
        all
    }

    pub fn set_alias(&self, alias: &str, target: &str) -> Result<(), String> {
        let path = self.system_root.join("aliases.json");
        let mut aliases = read_aliases(&path);
        aliases.insert(alias.to_string(), target.to_string());
        let text = serde_json::to_string_pretty(&aliases).map_err(|e| e.to_string())?;
        write_atomic(&path, text.as_bytes()).map_err(|e| e.to_string())
    }

    /// Accept a staged artifact into the store.
    ///
    /// The digest is verified *here*, in the process with no network, over the
    /// bytes actually on disk. `ai-daemon-fetch` is not trusted to have
    /// verified anything; it is trusted only to have put bytes somewhere (§9).
    pub fn accept_staged(
        &self,
        staged: &Path,
        mut manifest: Manifest,
        expected_digest: &str,
    ) -> Result<Manifest, String> {
        if !staged.starts_with(self.staging_dir()) {
            return Err(format!("{} is not in the staging directory", staged.display()));
        }
        let actual = digest_file(staged).map_err(|e| format!("hashing {}: {e}", staged.display()))?;
        if actual != expected_digest {
            let _ = std::fs::remove_file(staged);
            return Err(format!("digest mismatch: expected {expected_digest}, got {actual}"));
        }
        let size = std::fs::metadata(staged).map_err(|e| e.to_string())?.len();
        manifest.digest = actual.clone();
        if manifest.requirements.weights_bytes == 0 {
            manifest.requirements.weights_bytes = size;
        }

        let dest = self.system_root.join("blobs/sha256").join(hex_of(&actual)?);
        if dest.exists() {
            // Someone already has these exact bytes. Nothing to copy — this is
            // the sharing the store exists for, arriving for free.
            let _ = std::fs::remove_file(staged);
            info!("registry: {} already present by digest", manifest.name);
        } else {
            std::fs::rename(staged, &dest)
                .map_err(|e| format!("moving into store: {e}"))?;
            let _ = set_mode(&dest, 0o444);
        }

        let manifest_path = self.system_root.join("manifests").join(format!("{}.json", manifest.name));
        let text = serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?;
        write_atomic(&manifest_path, text.as_bytes()).map_err(|e| e.to_string())?;
        self.invalidate();
        info!(
            "registry: installed {} ({}, {} bytes, {})",
            manifest.name, manifest.format, manifest.requirements.weights_bytes, manifest.digest
        );
        Ok(manifest)
    }

    /// Record a model that has no bytes here.
    ///
    /// Separate from `accept_staged` on purpose. That function's entire job is
    /// to verify a digest before anything enters the store, and a remote model
    /// has nothing to verify — so rather than teach it a mode where it skips
    /// its one safety check, remote registration is a different function that
    /// visibly never had one. It writes a manifest and no blob.
    pub fn register_remote(&self, manifest: Manifest) -> Result<Manifest, String> {
        if !manifest.is_remote() {
            return Err(format!(
                "register_remote called for {} which is format {:?}",
                manifest.name, manifest.format
            ));
        }
        let manifest_path =
            self.system_root.join("manifests").join(format!("{}.json", manifest.name));
        let text = serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?;
        write_atomic(&manifest_path, text.as_bytes()).map_err(|e| e.to_string())?;
        self.invalidate();
        info!(
            "registry: registered remote model {} -> {} (no weights on this machine)",
            manifest.name, manifest.digest
        );
        Ok(manifest)
    }

    /// Remove a model by name. The blob survives if another manifest still
    /// points at the same digest — content addressing means removal is
    /// refcounted by definition.
    pub fn remove(&self, name: &str) -> Result<(), String> {
        let manifest_path = self.system_root.join("manifests").join(format!("{name}.json"));
        let manifest = read_manifest(&manifest_path)
            .ok_or_else(|| format!("no model named {name:?}"))?;
        std::fs::remove_file(&manifest_path).map_err(|e| e.to_string())?;
        self.invalidate();

        let still_referenced = self
            .system_manifests()
            .iter()
            .any(|m| m.digest == manifest.digest);
        if !still_referenced && !manifest.is_remote() {
            if let Ok(blob) = blob_path(&self.system_root, &manifest.digest) {
                let _ = std::fs::remove_file(blob);
            }
        }
        info!("registry: removed {name}");
        Ok(())
    }
}

/// Where a manifest's weights are, or nowhere at all.
///
/// A remote model resolves to an empty path rather than an error: it is a
/// perfectly good model, it just has no file. Every backend is handed this
/// path and the remote one ignores it; a local backend handed an empty path
/// fails when it opens it, which is the right failure for a manifest that
/// claimed the wrong format.
fn blob_for(root: &Path, manifest: &Manifest) -> Result<PathBuf, String> {
    if manifest.is_remote() {
        return Ok(PathBuf::new());
    }
    blob_path(root, &manifest.digest)
}

fn blob_path(root: &Path, digest: &str) -> Result<PathBuf, String> {
    Ok(root.join("blobs/sha256").join(hex_of(digest)?))
}

fn hex_of(digest: &str) -> Result<&str, String> {
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("unsupported digest {digest:?}; only sha256 in v1"))?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("malformed sha256 digest {digest:?}"));
    }
    Ok(hex)
}

pub fn digest_file(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn read_manifests(dir: &Path) -> Vec<Manifest> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut manifests: Vec<Manifest> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .filter_map(|p| read_manifest(&p))
        .collect();
    manifests.sort_by(|a, b| a.name.cmp(&b.name));
    manifests
}

fn read_manifest(path: &Path) -> Option<Manifest> {
    let text = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str(&text) {
        Ok(manifest) => Some(manifest),
        Err(e) => {
            warn!("registry: ignoring {} ({e})", path.display());
            None
        }
    }
}

fn read_aliases(path: &Path) -> BTreeMap<String, String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// `/etc/passwd` rather than `getpwuid`: the daemon runs with `ProtectHome`
/// and a locked-down NSS surface, and a home directory path is all we need.
fn home_of_uid(uid: u32) -> Option<PathBuf> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let mut fields = line.split(':');
        let (_name, _pw, entry_uid) = (fields.next()?, fields.next()?, fields.next()?);
        if entry_uid.parse::<u32>().ok()? == uid {
            let home = fields.nth(1)?;
            if home.is_empty() || home == "/" {
                return None;
            }
            return Some(PathBuf::from(home));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_daemon_proto::manifest::Requirements;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ai-daemon-reg-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn manifest(name: &str) -> Manifest {
        Manifest {
            name: name.into(),
            digest: String::new(),
            format: "mock".into(),
            quantization: String::new(),
            license: "MIT".into(),
            requirements: Requirements::default(),
            template: Default::default(),
            backend: "mock".into(),
            capabilities: vec!["generate".into()],
            source: "file:///dev/null".into(),
        }
    }

    fn stage(registry: &Registry, name: &str, bytes: &[u8]) -> (PathBuf, String) {
        let path = registry.staging_dir().join(format!("{name}.part"));
        std::fs::write(&path, bytes).unwrap();
        let digest = digest_file(&path).unwrap();
        (path, digest)
    }

    #[test]
    fn a_digest_mismatch_is_refused_and_the_artifact_destroyed() {
        let dir = scratch("mismatch");
        let registry = Registry::new(&dir, BTreeMap::new());
        let (path, _) = stage(&registry, "m", b"weights");
        let wrong = format!("sha256:{}", "0".repeat(64));

        let error = registry.accept_staged(&path, manifest("m"), &wrong).unwrap_err();
        assert!(error.contains("digest mismatch"), "{error}");
        assert!(!path.exists(), "an artifact that failed verification must not linger in staging");
        assert!(registry.list(None).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_artifact_from_outside_staging_is_refused() {
        let dir = scratch("outside");
        let registry = Registry::new(&dir, BTreeMap::new());
        let elsewhere = dir.join("not-staging.bin");
        std::fs::write(&elsewhere, b"weights").unwrap();
        let digest = digest_file(&elsewhere).unwrap();

        let error = registry.accept_staged(&elsewhere, manifest("m"), &digest).unwrap_err();
        assert!(error.contains("staging directory"), "{error}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The whole argument for the daemon owning models: two names, one file.
    #[test]
    fn two_names_for_the_same_bytes_share_one_blob() {
        let dir = scratch("share");
        let registry = Registry::new(&dir, BTreeMap::new());

        let (first, digest) = stage(&registry, "a", b"identical weights");
        registry.accept_staged(&first, manifest("a"), &digest).unwrap();
        let (second, digest2) = stage(&registry, "b", b"identical weights");
        assert_eq!(digest, digest2);
        registry.accept_staged(&second, manifest("b"), &digest).unwrap();

        let blobs: Vec<_> = std::fs::read_dir(dir.join("models/blobs/sha256")).unwrap().collect();
        assert_eq!(blobs.len(), 1, "content addressing means one copy");
        assert_eq!(registry.list(None).len(), 2);

        // And removing one name must not take the other's weights with it.
        registry.remove("a").unwrap();
        let blobs: Vec<_> = std::fs::read_dir(dir.join("models/blobs/sha256")).unwrap().collect();
        assert_eq!(blobs.len(), 1, "still referenced by b");
        registry.remove("b").unwrap();
        let blobs: Vec<_> = std::fs::read_dir(dir.join("models/blobs/sha256")).unwrap().collect();
        assert!(blobs.is_empty(), "the last reference takes the blob with it");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolving_follows_an_alias_exactly_one_hop() {
        let dir = scratch("alias");
        let registry = Registry::new(&dir, BTreeMap::new());
        let (path, digest) = stage(&registry, "small", b"weights");
        registry.accept_staged(&path, manifest("small"), &digest).unwrap();
        registry.set_alias("default", "small").unwrap();
        registry.set_alias("indirect", "default").unwrap();

        assert_eq!(registry.resolve("default", None).unwrap().manifest.name, "small");
        assert!(
            registry.resolve("indirect", None).is_err(),
            "an alias chain is a chain nobody can audit"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_config_alias_is_visible_without_being_written_to_the_store() {
        let dir = scratch("cfgalias");
        let mut aliases = BTreeMap::new();
        aliases.insert("fast".to_string(), "small".to_string());
        let registry = Registry::new(&dir, aliases);
        let (path, digest) = stage(&registry, "small", b"weights");
        registry.accept_staged(&path, manifest("small"), &digest).unwrap();

        assert_eq!(registry.resolve("fast", None).unwrap().manifest.name, "small");
        assert!(!dir.join("models/aliases.json").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_malformed_digest_is_rejected_before_it_becomes_a_path() {
        assert!(hex_of("sha256:../../etc/passwd").is_err());
        assert!(hex_of("md5:abc").is_err());
        assert!(hex_of(&format!("sha256:{}", "g".repeat(64))).is_err());
        assert!(hex_of(&format!("sha256:{}", "a".repeat(64))).is_ok());
    }

    #[test]
    fn the_digest_of_a_known_string_is_the_known_value() {
        let dir = scratch("digest");
        let path = dir.join("abc");
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(
            digest_file(&path).unwrap(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn removing_a_model_that_is_not_there_says_so() {
        let dir = scratch("missing");
        let registry = Registry::new(&dir, BTreeMap::new());
        assert!(registry.remove("nope").is_err());
        assert!(registry.resolve("nope", None).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
