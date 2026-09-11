//! `watch_strategy` entity (`oci_registry_poll`) — the POLLING change-watch
//! path.
//!
//! A registry has no change-push channel, but two cheap reads tell whether
//! an image moved: the digest a tag resolves to (a `HEAD` on the manifest),
//! and the tag list of a repository (a new version is a new tag). The
//! watcher polls one of them on a cadence — the tag's digest when the spec
//! names a `reference`, the repository's full tag set otherwise — and emits
//! `notifications/resources/updated` whenever the value differs from the
//! previous tick. The first tick only records a baseline, so a watcher never
//! fires spuriously at startup.
//!
//! The poll thread, the cursor diff, the stop signal and the opaque handle
//! round-trip live in the shared [`mcpg_plugin_sdk::watch`] helper; this
//! entity supplies the per-tick closure over the backend's own client. The
//! helper's loop is synchronous and the client is async, so a single
//! current-thread runtime is built once in [`watch`] and `block_on`s each
//! tick.

use std::time::Duration;

use mcpg_plugin_protocol::backend::WatchError;
use mcpg_plugin_protocol::{PluginManifest, firstparty_manifest};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::ffi::{SyncWatchStrategyPlugin, WatchHandleBox};
use mcpg_plugin_sdk::watch::{cancel_polling_watch, spawn_polling_watch};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::client::{MANIFEST_ACCEPT, RegistryClient};
use crate::config::{OciAuth, OciBackendSpec, OciTlsConfig, validate_digest};

/// The strategy discriminator this entity handles.
pub const WATCH_KIND: &str = "oci_registry_poll";

/// Bound on the tag pages one tick walks: 1000 tags per page × 50 pages is
/// far beyond any repository a change-watch is pointed at, and a bound is
/// what keeps a tick from becoming a crawl.
const MAX_TAG_PAGES: usize = 50;

fn default_interval_ms() -> u64 {
    60_000
}
fn default_timeout_ms() -> u64 {
    10_000
}

/// Per-watch spec: the registry connection (same shape as the binding) plus
/// the repository and, optionally, the tag to watch. Carried per watch, so a
/// watcher is self-contained.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchSpec {
    registry: String,
    #[serde(default)]
    auth: OciAuth,
    #[serde(default)]
    tls: OciTlsConfig,
    /// Repository to watch. REQUIRED.
    repository: String,
    /// A tag to watch by digest. Absent: the repository's tag set is watched
    /// instead, so a new version tag is the change.
    #[serde(default)]
    reference: Option<String>,
    #[serde(default)]
    allow_private_backends: bool,
    #[serde(default = "default_interval_ms")]
    interval_ms: u64,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}

/// `watch_strategy` entity. Stateless beyond its manifest — every watcher's
/// connection and target arrive on the per-watch spec.
pub struct OciRegistryWatchCdylib {
    manifest: PluginManifest,
}

impl OciRegistryWatchCdylib {
    /// Infallible cdylib factory. `config_json` + host are ignored — the
    /// watch carries no plugin-level config.
    pub fn from_host_config(_config_json: &str, _host: HostHandle) -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.oci-registry",
                name: "OCI Registry Poll Watch Strategy",
                class: WatchStrategy,
            },
        }
    }
}

/// One tick: the digest the tag resolves to, or the fingerprint of the tag
/// set. `Ok(None)` is "no signal" (a 404 on a tag that does not exist yet,
/// an empty repository); a transport failure is `Err` for the helper to log
/// and retry.
async fn poll_once(
    client: &RegistryClient,
    repository: &str,
    reference: Option<&str>,
) -> Result<Option<String>, String> {
    match reference {
        Some(tag) => {
            let path = format!("/v2/{repository}/manifests/{tag}");
            let scope = format!("repository:{repository}:pull");
            let head = client.head(&path, MANIFEST_ACCEPT, &scope).await?;
            match (head.status, head.header("docker-content-digest")) {
                (200, Some(d)) if validate_digest(d).is_ok() => Ok(Some(d.to_owned())),
                (200, _) => {
                    // No digest header: hash the manifest bytes instead.
                    let got = client.get(&path, MANIFEST_ACCEPT, &scope).await?;
                    if got.status != 200 {
                        return Ok(None);
                    }
                    Ok(Some(format!("sha256:{:x}", Sha256::digest(&got.body))))
                }
                (404, _) => Ok(None),
                (status, _) => Err(format!("registry answered {status} for {repository}:{tag}")),
            }
        }
        None => {
            let scope = format!("repository:{repository}:pull");
            let mut tags: Vec<String> = Vec::new();
            let mut last: Option<String> = None;
            for _ in 0..MAX_TAG_PAGES {
                let mut path = format!("/v2/{repository}/tags/list?n=1000");
                if let Some(l) = &last {
                    path.push_str("&last=");
                    path.push_str(&l.replace('/', "%2F"));
                }
                let resp = client.get(&path, "application/json", &scope).await?;
                if resp.status == 404 {
                    return Ok(None);
                }
                if resp.status != 200 {
                    return Err(format!(
                        "registry answered {} for {repository} tags",
                        resp.status
                    ));
                }
                let body = resp
                    .json()
                    .ok_or_else(|| "tags body is not JSON".to_owned())?;
                let page: Vec<String> = body
                    .get("tags")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default();
                tags.extend(page);
                match crate::ops::next_page_cursor(&resp) {
                    Some(next) if Some(&next) != last.as_ref() => last = Some(next),
                    _ => break,
                }
            }
            if tags.is_empty() {
                return Ok(None);
            }
            tags.sort();
            tags.dedup();
            let mut h = Sha256::new();
            for t in &tags {
                h.update(t.as_bytes());
                h.update(b"\n");
            }
            Ok(Some(format!("tags:{}:{:x}", tags.len(), h.finalize())))
        }
    }
}

impl SyncWatchStrategyPlugin for OciRegistryWatchCdylib {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        WATCH_KIND
    }

    fn watch(
        &self,
        resource_uri: &str,
        spec: &Value,
        emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, WatchError> {
        let parsed: WatchSpec =
            serde_json::from_value(spec.clone()).map_err(|e| WatchError::InvalidSpec {
                message: format!("invalid {WATCH_KIND} watch spec: {e}"),
            })?;
        let invalid = |m: String| WatchError::InvalidSpec { message: m };
        if parsed.repository.trim().is_empty() {
            return Err(invalid("repository must not be empty".into()));
        }

        // Reuse the binding's validation and client by synthesising a
        // read-only `resolve` spec: the watched repository is its sole
        // default, so the same grammar and origin guards apply.
        let backend_spec_json = json!({
            "registry": parsed.registry,
            "operation": "resolve",
            "default_repository": parsed.repository,
            "default_reference": parsed.reference,
            "auth": serde_json::to_value(&parsed.auth).map_err(|e| invalid(e.to_string()))?,
            "tls": serde_json::to_value(&parsed.tls).map_err(|e| invalid(e.to_string()))?,
            "allow_private_backends": parsed.allow_private_backends,
            "operation_timeout_ms": parsed.timeout_ms.max(1),
            "connect_timeout_ms": parsed.timeout_ms.max(1),
        });
        let backend_spec =
            OciBackendSpec::parse(&backend_spec_json).map_err(|e| invalid(e.to_string()))?;
        let client = RegistryClient::new(&backend_spec).map_err(|e| WatchError::Subscribe {
            message: format!("{WATCH_KIND}: client init: {e}"),
        })?;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| WatchError::Subscribe {
                message: format!("{WATCH_KIND}: runtime init: {e}"),
            })?;
        let repository = backend_spec.default_repository.clone().unwrap_or_default();
        let reference = backend_spec.default_reference.clone();
        let interval = Duration::from_millis(parsed.interval_ms);

        let handle = spawn_polling_watch(resource_uri, interval, emit_event, move || {
            rt.block_on(poll_once(&client, &repository, reference.as_deref()))
        });
        Ok(handle)
    }

    fn cancel(&self, handle: WatchHandleBox) {
        cancel_polling_watch(handle);
    }
}
