//! `dev.mcpg.backend.oci-registry` — OCI container-registry backend binding
//! plugin.
//!
//! One binding == one read-only distribution operation against one
//! registry (the `http`/`elasticsearch` envelope model): the operator
//! declares `backend: { kind: oci_registry, registry, operation,
//! repository_allowlist, ... }` and that binding becomes one MCP tool. Per
//! call the arguments name a repository (when the binding admits a choice),
//! a reference and paging, the plugin issues the distribution requests —
//! completing the registry's token challenge, following storage redirects
//! under guard, verifying every manifest and blob against its digest — and
//! shapes the result into a stable envelope.
//!
//! Operations: `catalog`, `tags`, `resolve`, `manifest`, `image_config`,
//! `referrers`. Nothing pushes, deletes or fetches a layer.
//!
//! A second `watch_strategy` entity (kind `oci_registry_poll`) lets a
//! resource subscribe to a tag's digest or a repository's tag set by
//! polling — see [`watch`].

mod client;
mod config;
mod ops;
mod surface;
pub mod watch;

#[cfg(any(feature = "cdylib-export", feature = "static-firstparty"))]
mod cdylib;

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{
    BackendError, BackendHost, BackendPlugin, BackendRequest, BackendResponse, ListedResource,
    PluginManifest, ResourcePage, firstparty_manifest,
};
use mcpg_plugin_sdk::HostHandle;
use serde_json::{Value, json};
use tracing::debug;

pub use config::{OciAuth, OciBackendSpec, OciOperation, OciTlsConfig, SpecError};
pub use surface::Surface;

pub const PLUGIN_ID: &str = "dev.mcpg.backend.oci-registry";

/// Sentinel wrapper the gateway projects verbatim as a `CallToolResult`
/// (so we can return `isError: true` tool-level errors). Matches the host
/// + mock-backend constant.
const VERBATIM_RESULT_KEY: &str = "__mcpg_verbatim_result";

/// Completion candidates returned per variable, at most.
const MAX_COMPLETIONS: usize = 100;

struct OciProfile {
    spec: OciBackendSpec,
    client: client::RegistryClient,
}

/// `BackendPlugin` for `kind: "oci_registry"`.
pub struct OciRegistryBackendPlugin {
    manifest: PluginManifest,
    // std RwLock: guards are never held across `.await` (the client is
    // built before the write lock is taken; `execute` clones the Arc out
    // before awaiting).
    profiles: RwLock<BTreeMap<String, Arc<OciProfile>>>,
    /// Unified host surface for per-call observability. Installed once at
    /// boot by the gateway before any `execute()` traffic; `None` in test
    /// harnesses (the triad short-circuits to a no-op).
    host_handle: OnceLock<HostHandle>,
}

impl Default for OciRegistryBackendPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl OciRegistryBackendPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.oci-registry",
                name: "OCI Registry Binding",
                class: Backend,
            },
            profiles: RwLock::new(BTreeMap::new()),
            host_handle: OnceLock::new(),
        }
    }

    /// No plugin-level config — per-binding connection + operation details
    /// arrive via `register_profile`.
    pub fn from_config_json(_config_json: &str) -> Self {
        Self::new()
    }

    /// Install the unified [`HostHandle`]. Idempotent — a second call is a
    /// no-op. Returns whether the slot was filled.
    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.host_handle.set(host).is_ok()
    }

    fn host_handle(&self) -> Option<&HostHandle> {
        self.host_handle.get()
    }

    fn profile(&self, name: &str) -> Option<Arc<OciProfile>> {
        self.profiles
            .read()
            .expect("profiles lock poisoned")
            .get(name)
            .cloned()
    }

    fn require_profile(&self, name: &str) -> Result<Arc<OciProfile>, BackendError> {
        self.profile(name)
            .ok_or_else(|| BackendError::ProfileNotFound {
                backend_name: name.to_owned(),
            })
    }

    /// Emit the per-call observability triad (latency histogram + counter +
    /// optional audit event) through the installed [`HostHandle`].
    /// Short-circuits when no handle is installed (test paths).
    #[allow(clippy::too_many_arguments)]
    async fn emit_host_observability(
        &self,
        backend_name: &str,
        outcome_label: &'static str,
        status_code: Option<u16>,
        reason: Option<&str>,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        duration: Duration,
    ) {
        let Some(host) = self.host_handle() else {
            return;
        };
        host.histogram(
            "mcpg_oci_registry_backend_latency_seconds",
            duration.as_secs_f64(),
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_oci_registry_backend_calls_total",
            1,
            &[("outcome", outcome_label)],
        );

        if let Some(action) = audit_action_for_outcome(outcome_label) {
            let actor = identity.cloned().unwrap_or_else(synthetic_system_identity);
            let mut details = json!({
                "backend": backend_name,
                "duration_ms": duration.as_millis() as u64,
                "outcome": outcome_label,
                "alias": host.alias(),
            });
            if let Some(status) = status_code {
                details
                    .as_object_mut()
                    .expect("json object")
                    .insert("status_code".into(), Value::from(status));
            }
            if let Some(reason) = reason {
                details
                    .as_object_mut()
                    .expect("json object")
                    .insert("reason".into(), Value::String(reason.to_owned()));
            }
            let event = AuditEvent {
                event_id: format!("oci-{}-{}", request_id, duration.as_nanos()),
                occurred_at: rfc3339_now(),
                actor,
                action: action.to_owned(),
                resource: Some(format!("oci-binding://{backend_name}")),
                outcome: AuditOutcome::Failure,
                request_id: Some(request_id.to_owned()),
                upstream_request_id: None,
                node_id: None,
                details,
                prev_event_hash: None,
            };
            let host_for_audit = host.clone();
            if let Err(join_err) = tokio::task::spawn_blocking(move || {
                let _ = host_for_audit.audit_event(event);
            })
            .await
            {
                debug!(
                    target: "mcpg::oci_registry::host_handle",
                    error = %join_err,
                    "host_handle.audit_event spawn_blocking failed"
                );
            }
        }
    }
}

impl std::fmt::Debug for OciRegistryBackendPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OciRegistryBackendPlugin")
            .field("id", &self.manifest.id)
            .finish()
    }
}

/// Bounded outcome label for the unified host-handle metric pair. The set
/// MUST stay closed so the host metrics recorder doesn't blow up on
/// cardinality. 4xx/5xx are class-bucketed.
fn host_outcome_label_for_status(status: u16) -> &'static str {
    match status {
        200..=299 => "ok",
        400..=499 => "registry_4xx",
        500..=599 => "registry_5xx",
        _ => "ok",
    }
}

/// Bounded outcome label for the transport-error path (no HTTP status).
fn host_outcome_label_for_transport_error(message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        "timeout"
    } else {
        "transport"
    }
}

/// Bounded set of dotted audit-event action names emitted on notable
/// failures. `None` for success + 4xx (normal traffic). Driver-class
/// failures (timeout / transport / 5xx) and a digest mismatch emit so
/// operators can reconstruct upstream outages and tampering.
fn audit_action_for_outcome(label: &str) -> Option<&'static str> {
    match label {
        "timeout" => Some("dev.mcpg.backend.oci-registry.request_timeout"),
        "transport" => Some("dev.mcpg.backend.oci-registry.request_failed"),
        "registry_5xx" => Some("dev.mcpg.backend.oci-registry.upstream_5xx"),
        "digest_mismatch" => Some("dev.mcpg.backend.oci-registry.digest_mismatch"),
        _ => None,
    }
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Synthetic identity for audit events on system-initiated calls (no
/// caller attribution).
fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some(PLUGIN_ID.into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

fn verbatim_error(msg: &str) -> Vec<u8> {
    let envelope = json!({
        VERBATIM_RESULT_KEY: {
            "content": [ { "type": "text", "text": msg } ],
            "isError": true,
        }
    });
    serde_json::to_vec(&envelope).unwrap_or_else(|_| b"{}".to_vec())
}

fn tool_error(msg: &str) -> BackendResponse {
    BackendResponse {
        payload: verbatim_error(msg),
        truncated: false,
    }
}

/// The resource URI for one listed item.
fn oci_uri(host: &str, repository: &str, reference: Option<&str>) -> String {
    match reference {
        Some(r) if config::is_digest(r) => format!("oci://{host}/{repository}@{r}"),
        Some(r) => format!("oci://{host}/{repository}:{r}"),
        None => format!("oci://{host}/{repository}"),
    }
}

/// On the resource surface the requested URI names the repository and
/// reference; fold them into the arguments unless the call already carries
/// them. A URI on a different registry is refused.
fn fold_uri_into_args(spec: &OciBackendSpec, args: &mut Value) -> Result<(), String> {
    let Some(uri) = surface::resolve_resource_uri(spec.uri.as_deref(), args).map(str::to_owned)
    else {
        return Ok(());
    };
    let Some((host, repository, reference)) = surface::parse_oci_uri(&uri) else {
        return Ok(());
    };
    if host != spec.host() {
        return Err(format!(
            "resource URI names registry {host:?}; this binding serves {:?}",
            spec.host()
        ));
    }
    let obj = args
        .as_object_mut()
        .ok_or_else(|| "tool arguments must be an object".to_owned())?;
    obj.entry("repository").or_insert_with(|| json!(repository));
    if let Some(r) = reference {
        obj.entry("reference").or_insert_with(|| json!(r));
    }
    Ok(())
}

#[async_trait]
impl BackendPlugin for OciRegistryBackendPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "oci_registry"
    }

    async fn register_profile(
        &self,
        profile_name: &str,
        spec: &Value,
        host: Arc<dyn BackendHost>,
    ) -> Result<(), BackendError> {
        let _ = &host; // cred:// resolution happens per-call via the cdylib-bridged host
        let parsed = OciBackendSpec::parse(spec).map_err(|e| BackendError::InvalidSpec {
            message: e.to_string(),
        })?;
        if parsed.allow_any_repository {
            tracing::warn!(
                target: "mcpg::oci_registry",
                backend = %profile_name,
                "oci_registry binding registered with allow_any_repository — repository allowlist bypassed"
            );
        }
        let client =
            client::RegistryClient::new(&parsed).map_err(|e| BackendError::InvalidSpec {
                message: format!("oci_registry client init: {e}"),
            })?;
        debug!(
            target: "mcpg::oci_registry",
            backend = %profile_name,
            operation = %parsed.operation.as_str(),
            registry = %parsed.host(),
            "registered oci_registry binding profile"
        );
        self.profiles
            .write()
            .expect("profiles lock poisoned")
            .insert(
                profile_name.to_owned(),
                Arc::new(OciProfile {
                    spec: parsed,
                    client,
                }),
            );
        Ok(())
    }

    async fn execute(
        &self,
        profile_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        let t0 = Instant::now();
        let request_id = request.request_id.clone();
        let identity = request.identity.clone();
        let profile = self.require_profile(profile_name)?;

        // Parse tool arguments. Bad JSON is a tool-level error (the caller
        // sent garbage), NOT a backend transport failure.
        let mut args: Value = if request.payload.is_empty() {
            json!({})
        } else {
            match serde_json::from_slice(&request.payload) {
                Ok(v) => v,
                Err(e) => return Ok(tool_error(&format!("invalid tool arguments JSON: {e}"))),
            }
        };
        if !args.is_object() {
            return Ok(tool_error("tool arguments must be an object"));
        }
        if profile.spec.surface == Surface::Resource
            && let Err(m) = fold_uri_into_args(&profile.spec, &mut args)
        {
            return Ok(tool_error(&m));
        }
        let call = match ops::resolve_call(&profile.spec, &args) {
            Ok(c) => c,
            Err(ops::OpError::Call(m)) | Err(ops::OpError::Transport(m)) => {
                return Ok(tool_error(&m));
            }
        };

        let outcome = ops::run(&profile.client, &profile.spec, &call, &args).await;
        let (label, status, reason) = match &outcome {
            Ok(out) => {
                let label = host_outcome_label_for_status(out.status);
                let reason = (!out.ok).then(|| format!("upstream status {}", out.status));
                (label, Some(out.status), reason)
            }
            Err(ops::OpError::Call(m)) if m.contains("hash to") => {
                ("digest_mismatch", None, Some(m.clone()))
            }
            Err(ops::OpError::Call(m)) => ("ok", None, Some(m.clone())),
            Err(ops::OpError::Transport(m)) => (
                host_outcome_label_for_transport_error(m),
                None,
                Some(m.clone()),
            ),
        };
        self.emit_host_observability(
            profile_name,
            label,
            status,
            reason.as_deref(),
            identity.as_ref(),
            request_id.as_str(),
            t0.elapsed(),
        )
        .await;

        match outcome {
            Ok(out) => {
                let envelope = ops::envelope(&profile.spec, &call, &out);
                // The resource surface reshapes a successful result into the
                // `{contents}` body; a failed one keeps the envelope so the
                // decoder sees `downstreamError`, not an invalid body.
                let body = if out.ok && profile.spec.surface == Surface::Resource {
                    let uri = surface::resolve_resource_uri(profile.spec.uri.as_deref(), &args)
                        .map(str::to_owned)
                        .unwrap_or_else(|| {
                            oci_uri(
                                &profile.spec.host(),
                                call.repository.as_deref().unwrap_or_default(),
                                call.reference.as_deref(),
                            )
                        });
                    surface::resource_contents_body(&uri, &out.response)
                } else {
                    envelope
                };
                let payload = serde_json::to_vec(&body).map_err(|e| BackendError::Transport {
                    message: format!("oci_registry envelope serialization failed: {e}"),
                })?;
                Ok(BackendResponse {
                    payload,
                    truncated: profile.spec.surface == Surface::Tool && out.truncated,
                })
            }
            Err(ops::OpError::Call(m)) => Ok(tool_error(&m)),
            Err(ops::OpError::Transport(m)) => {
                if host_outcome_label_for_transport_error(&m) == "timeout" {
                    Err(BackendError::Timeout {
                        timeout_ms: profile.spec.operation_timeout_ms,
                    })
                } else {
                    Err(BackendError::Transport { message: m })
                }
            }
        }
    }

    fn input_schema(&self, profile_name: &str) -> Option<Value> {
        self.profile(profile_name)
            .map(|p| ops::input_schema(&p.spec))
    }

    /// JSON Schema for the response envelope this binding emits.
    fn output_schema(&self, _profile_name: &str) -> Option<Value> {
        Some(ops::result_envelope_schema())
    }

    fn audit_metadata(&self, profile_name: &str) -> serde_json::Map<String, Value> {
        let mut m = serde_json::Map::new();
        if let Some(p) = self.profile(profile_name) {
            m.insert(
                "oci.operation".into(),
                Value::String(p.spec.operation.as_str().to_owned()),
            );
            m.insert("oci.registry".into(), Value::String(p.spec.host()));
            m.insert(
                "oci.repository_mode".into(),
                Value::String(if p.spec.allow_any_repository {
                    "any".to_owned()
                } else {
                    "allowlist".to_owned()
                }),
            );
        }
        m
    }

    /// Enumerate resources for `resources/list`: the tags of the binding's
    /// default repository as `oci://<registry>/<repository>:<tag>` entries
    /// (a `catalog` binding lists repositories instead). The cursor is the
    /// registry's own `last` paging value. Bindings with neither inherit the
    /// empty page.
    async fn list_resources(
        &self,
        profile_name: &str,
        cursor: Option<&str>,
    ) -> Result<ResourcePage, BackendError> {
        let profile = self.require_profile(profile_name)?;
        let spec = &profile.spec;
        let mut args = json!({});
        if let Some(c) = cursor {
            args["last"] = json!(c);
        }
        let host = spec.host();
        let page = if spec.operation == OciOperation::Catalog {
            let listing = run_listing(&profile, OciOperation::Catalog, None, &args).await?;
            let items = listing
                .response
                .get("repositories")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            ResourcePage {
                resources: items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|repo| ListedResource {
                        uri: oci_uri(&host, repo, None),
                        name: Some(repo.to_owned()),
                        description: None,
                        mime_type: Some("application/json".into()),
                    })
                    .collect(),
                next_cursor: listing
                    .response
                    .get("next_last")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            }
        } else {
            let Some(repository) = spec.default_repository.clone() else {
                return Ok(ResourcePage::empty());
            };
            let listing =
                run_listing(&profile, OciOperation::Tags, Some(&repository), &args).await?;
            let tags = listing
                .response
                .get("tags")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            ResourcePage {
                resources: tags
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|tag| ListedResource {
                        uri: oci_uri(&host, &repository, Some(tag)),
                        name: Some(format!("{repository}:{tag}")),
                        description: None,
                        mime_type: Some("application/json".into()),
                    })
                    .collect(),
                next_cursor: listing
                    .response
                    .get("next_last")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            }
        };
        Ok(page)
    }

    /// Completion candidates for a resource-template variable: `repository`
    /// from the catalog (allowlist-filtered), `reference` from the tags of
    /// the repository named in the context (or the binding default).
    async fn complete_template_variable(
        &self,
        profile_name: &str,
        variable_name: &str,
        prefix: &str,
        _config: &Value,
        context: &BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        let profile = self.require_profile(profile_name)?;
        let spec = &profile.spec;
        let args = json!({ "n": 1000 });
        let candidates: Vec<String> = match variable_name {
            "repository" => {
                let listing = run_listing(&profile, OciOperation::Catalog, None, &args).await?;
                listing
                    .response
                    .get("repositories")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default()
            }
            "reference" | "tag" => {
                let repository = match context
                    .get("repository")
                    .cloned()
                    .or_else(|| spec.default_repository.clone())
                {
                    Some(r) => spec
                        .resolve_repository(Some(&r))
                        .map_err(|m| BackendError::InvalidSpec { message: m })?,
                    None => return Ok(Vec::new()),
                };
                let listing =
                    run_listing(&profile, OciOperation::Tags, Some(&repository), &args).await?;
                listing
                    .response
                    .get("tags")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default()
            }
            _ => return Ok(Vec::new()),
        };
        Ok(candidates
            .into_iter()
            .filter(|c| c.starts_with(prefix))
            .take(MAX_COMPLETIONS)
            .collect())
    }
}

/// Run a listing operation (`catalog` / `tags`) for a profile regardless of
/// the profile's own operation — the resource plane lists what the binding
/// can reach. Non-2xx and transport failures surface as `Transport`.
async fn run_listing(
    profile: &OciProfile,
    operation: OciOperation,
    repository: Option<&str>,
    args: &Value,
) -> Result<ops::Outcome, BackendError> {
    let mut spec = profile.spec.clone();
    spec.operation = operation;
    let call = ops::Call {
        repository: repository.map(str::to_owned),
        reference: None,
    };
    let out = ops::run(&profile.client, &spec, &call, args)
        .await
        .map_err(|e| match e {
            ops::OpError::Call(m) | ops::OpError::Transport(m) => BackendError::Transport {
                message: format!("oci_registry {} listing: {m}", operation.as_str()),
            },
        })?;
    if !out.ok {
        return Err(BackendError::Transport {
            message: format!(
                "oci_registry {} listing returned status {}",
                operation.as_str(),
                out.status
            ),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoOpHost;

    #[async_trait]
    impl BackendHost for NoOpHost {
        async fn invoke_tool(
            &self,
            _ctx: &mcpg_plugin_protocol::BackendInvocationContext,
            _tool_name: &str,
            _args: &Value,
        ) -> Result<Value, mcpg_plugin_protocol::BackendHostError> {
            Err(mcpg_plugin_protocol::BackendHostError::NotImplemented)
        }
    }

    fn host() -> Arc<dyn BackendHost> {
        Arc::new(NoOpHost)
    }

    #[tokio::test]
    async fn register_refuses_a_bad_spec_and_execute_an_unknown_profile() {
        let plugin = OciRegistryBackendPlugin::new();
        let err = plugin
            .register_profile(
                "t",
                &json!({ "registry": "ftp://x", "operation": "tags" }),
                host(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
        let err = plugin
            .execute(
                "missing",
                BackendRequest {
                    payload: b"{}".to_vec(),
                    headers: vec![],
                    request_id: "r".into(),
                    session_id: None,
                    identity: None,
                    idempotency: None,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, BackendError::ProfileNotFound { .. }));
    }

    #[tokio::test]
    async fn bad_arguments_are_tool_errors_not_transport_failures() {
        let plugin = OciRegistryBackendPlugin::new();
        plugin
            .register_profile(
                "t",
                &json!({
                    "registry": "https://ghcr.io",
                    "operation": "tags",
                    "repository_allowlist": ["acme/*"],
                }),
                host(),
            )
            .await
            .unwrap();
        let mk = |payload: &str| BackendRequest {
            payload: payload.as_bytes().to_vec(),
            headers: vec![],
            request_id: "r".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        for (payload, needle) in [
            ("{not json", "invalid tool arguments JSON"),
            ("{}", "`repository` argument is required"),
            (r#"{"repository": "evil/app"}"#, "not admitted"),
            (r#"{"repository": "Acme/App"}"#, "not a valid OCI name"),
        ] {
            let resp = plugin.execute("t", mk(payload)).await.unwrap();
            let body: Value = serde_json::from_slice(&resp.payload).unwrap();
            let text = body[VERBATIM_RESULT_KEY]["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            assert_eq!(
                body[VERBATIM_RESULT_KEY]["isError"],
                json!(true),
                "{payload}"
            );
            assert!(text.contains(needle), "{payload}: {text}");
        }
        assert_eq!(
            plugin.audit_metadata("t")["oci.repository_mode"],
            json!("allowlist")
        );
        let schema = plugin.input_schema("t").unwrap();
        assert_eq!(schema["required"], json!(["repository"]));
        assert!(plugin.output_schema("t").is_some());
    }

    #[test]
    fn resource_uris_carry_tag_or_digest() {
        assert_eq!(
            oci_uri("ghcr.io", "a/b", Some("v1")),
            "oci://ghcr.io/a/b:v1"
        );
        assert_eq!(
            oci_uri("ghcr.io", "a/b", Some("sha256:abc")),
            "oci://ghcr.io/a/b@sha256:abc"
        );
        assert_eq!(oci_uri("ghcr.io", "a/b", None), "oci://ghcr.io/a/b");
    }

    #[test]
    fn a_resource_uri_fills_repository_and_reference_but_never_overrides_them() {
        let spec: OciBackendSpec = serde_json::from_value(json!({
            "registry": "https://ghcr.io", "operation": "image_config",
            "repository_allowlist": ["acme/*"], "surface": "resource",
        }))
        .unwrap();
        let mut args = json!({ "uri": "oci://ghcr.io/acme/app:v2" });
        fold_uri_into_args(&spec, &mut args).unwrap();
        assert_eq!(args["repository"], "acme/app");
        assert_eq!(args["reference"], "v2");
        let mut args = json!({ "uri": "oci://ghcr.io/acme/app:v2", "reference": "v9" });
        fold_uri_into_args(&spec, &mut args).unwrap();
        assert_eq!(args["reference"], "v9");
        let mut args = json!({ "uri": "oci://docker.io/acme/app:v2" });
        assert!(
            fold_uri_into_args(&spec, &mut args).is_err(),
            "another registry is refused"
        );
    }

    #[test]
    fn outcome_labels_stay_closed() {
        assert_eq!(host_outcome_label_for_status(200), "ok");
        assert_eq!(host_outcome_label_for_status(404), "registry_4xx");
        assert_eq!(host_outcome_label_for_status(503), "registry_5xx");
        assert_eq!(
            host_outcome_label_for_transport_error("operation timed out"),
            "timeout"
        );
        assert_eq!(
            host_outcome_label_for_transport_error("connection refused"),
            "transport"
        );
        assert!(audit_action_for_outcome("ok").is_none());
        assert!(audit_action_for_outcome("registry_4xx").is_none());
        assert!(audit_action_for_outcome("digest_mismatch").is_some());
    }
}
