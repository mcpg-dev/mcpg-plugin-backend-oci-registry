//! Binding config (`backend: { kind: oci_registry, ... }`) — parse + validate.
//!
//! One binding is one operation against one registry. The registry, the
//! repositories the binding may reach, the credential and the transport
//! limits are operator-fixed; the model supplies only the repository (when
//! the binding allows a choice), the reference and the paging cursor.
//!
//! Repository names, tags and digests follow the OCI distribution grammar
//! and are validated before they are ever spliced into a request path — a
//! name is a path segment sequence by construction, so a value that fails
//! the grammar is refused rather than escaped.
//!
//! No `deny_unknown_fields` on the top-level spec: the gateway injects
//! `__mcpg_secret_refs` (and `__mcpg_id_sig`) before registration. The nested
//! `OciAuth` / `OciTlsConfig` carry it, so a typo there is caught.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::surface::Surface;

/// The operation a binding performs. Read-only by construction: the plugin
/// never pushes, deletes or downloads layers, so no operation can change a
/// registry or pull a payload larger than a manifest or an image config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OciOperation {
    /// `GET /v2/_catalog` — repositories the registry lists, filtered to the
    /// binding's allowlist.
    Catalog,
    /// `GET /v2/<name>/tags/list` — the tags of one repository.
    Tags,
    /// `HEAD /v2/<name>/manifests/<ref>` — the digest a tag currently points at.
    Resolve,
    /// `GET /v2/<name>/manifests/<ref>` — the manifest (or image index) itself.
    Manifest,
    /// The image config behind a reference (index → platform → config blob):
    /// labels, entrypoint, environment, architecture, layers.
    ImageConfig,
    /// `GET /v2/<name>/referrers/<digest>` — artifacts attached to a digest
    /// (signatures, SBOMs, attestations), with the tag-schema fallback for
    /// registries predating the referrers API.
    Referrers,
}

impl OciOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            OciOperation::Catalog => "catalog",
            OciOperation::Tags => "tags",
            OciOperation::Resolve => "resolve",
            OciOperation::Manifest => "manifest",
            OciOperation::ImageConfig => "image_config",
            OciOperation::Referrers => "referrers",
        }
    }

    /// Whether the operation addresses one repository (everything but the
    /// registry-wide catalog).
    pub fn needs_repository(self) -> bool {
        !matches!(self, OciOperation::Catalog)
    }

    /// Whether the operation addresses one reference within a repository.
    pub fn needs_reference(self) -> bool {
        matches!(
            self,
            OciOperation::Resolve
                | OciOperation::Manifest
                | OciOperation::ImageConfig
                | OciOperation::Referrers
        )
    }
}

/// Auth surface. The secret-bearing fields carry `cred://<plugin>/<target>`
/// (resolved per-caller at dispatch) and/or `${env.X}` (resolved at config
/// load). `kind: none` still completes the registry's anonymous token
/// challenge, which is how public repositories on Docker Hub and GHCR are
/// read.
#[derive(Clone, Deserialize, Serialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OciAuth {
    #[default]
    None,
    /// HTTP Basic, also presented to the token realm when the registry
    /// answers with a bearer challenge (the distribution token flow).
    Basic { username: String, password: String },
    /// A static bearer token sent as-is; the challenge flow is skipped.
    Bearer { token: String },
}

// Redacting `Debug` — the secret-bearing fields never reach a `{:?}`.
impl std::fmt::Debug for OciAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OciAuth::None => f.write_str("None"),
            OciAuth::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"***")
                .finish(),
            OciAuth::Bearer { .. } => f.debug_struct("Bearer").field("token", &"***").finish(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct OciTlsConfig {
    /// Inline PEM CA bundle for a private / self-signed registry CA.
    #[serde(default)]
    pub ca_cert_pem: Option<String>,
    /// Skip server cert verification. Honoured only when the registry is
    /// loopback; register fails otherwise.
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

impl std::fmt::Debug for OciTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OciTlsConfig")
            .field("ca_cert_pem", &self.ca_cert_pem.as_ref().map(|_| "<pem>"))
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .finish()
    }
}

fn default_connect_timeout_ms() -> u64 {
    5_000
}
fn default_operation_timeout_ms() -> u64 {
    30_000
}
/// Manifests and image configs are small documents; a registry answering
/// with more than this is not answering with one.
fn default_max_response_bytes() -> usize {
    4 * 1024 * 1024
}
fn default_page_size() -> u64 {
    100
}
fn default_platform() -> String {
    "linux/amd64".to_owned()
}

/// The binding spec.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OciBackendSpec {
    /// Registry origin, e.g. `https://ghcr.io` or `https://registry-1.docker.io`.
    /// `https://` required; `http://` is admitted for loopback only.
    pub registry: String,
    pub operation: OciOperation,
    /// Repositories the binding may address: exact names (`org/app`) or a
    /// prefix ending in `/*` (`org/*`). `default_repository` is always
    /// admitted; an empty list admits nothing else.
    #[serde(default)]
    pub repository_allowlist: Vec<String>,
    /// The repository used when the call names none.
    #[serde(default)]
    pub default_repository: Option<String>,
    /// Admit any repository the registry serves. The catalog then lists
    /// everything the credential can see.
    #[serde(default)]
    pub allow_any_repository: bool,
    /// The reference used when the call names none (`image_config` /
    /// `manifest` / `resolve`); `latest` when unset.
    #[serde(default)]
    pub default_reference: Option<String>,
    /// Platform selected out of a multi-platform index when the call names
    /// none, as `os/arch[/variant]`.
    #[serde(default = "default_platform")]
    pub default_platform: String,
    #[serde(default)]
    pub auth: OciAuth,
    #[serde(default)]
    pub tls: OciTlsConfig,
    /// Allow private/loopback resolved addresses (in-cluster registries).
    #[serde(default)]
    pub allow_private_backends: bool,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_operation_timeout_ms")]
    pub operation_timeout_ms: u64,
    /// Cap on any single response body read.
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
    /// Page size for `catalog` / `tags` and for `resources/list`.
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    /// Which MCP surface the binding serves.
    #[serde(default)]
    pub surface: Surface,
    /// Static resource URI for the resource surface.
    #[serde(default)]
    pub uri: Option<String>,
    /// Gateway-injected `cred://` bookkeeping; never operator-authored.
    #[serde(default, rename = "__mcpg_secret_refs", skip_serializing)]
    pub secret_refs: Vec<String>,
}

#[derive(Debug, Error)]
pub enum SpecError {
    #[error("{0}")]
    Invalid(String),
    #[error("spec deserialization: {0}")]
    Deserialize(#[from] serde_json::Error),
}

impl OciBackendSpec {
    pub fn parse(spec: &Value) -> Result<Self, SpecError> {
        let parsed: Self = serde_json::from_value(spec.clone())?;
        parsed.validate()?;
        Ok(parsed)
    }

    fn validate(&self) -> Result<(), SpecError> {
        let invalid = |m: String| SpecError::Invalid(m);
        let url = url::Url::parse(self.registry.trim())
            .map_err(|e| invalid(format!("registry is not a URL: {e}")))?;
        let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        match url.scheme() {
            "https" => {}
            "http" if loopback => {}
            other => {
                return Err(invalid(format!(
                    "registry must be https:// (http:// is admitted for localhost only), got {other}://"
                )));
            }
        }
        if url.host_str().is_none() {
            return Err(invalid("registry has no host".into()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(invalid(
                "registry must not carry userinfo — use `auth`".into(),
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(invalid(
                "registry must not carry a query or fragment".into(),
            ));
        }
        if self.tls.insecure_skip_verify && !loopback {
            return Err(invalid(
                "tls.insecure_skip_verify is honoured for a loopback registry only".into(),
            ));
        }
        for entry in &self.repository_allowlist {
            let bare = entry.strip_suffix("/*").unwrap_or(entry);
            validate_repository(bare)
                .map_err(|e| invalid(format!("repository_allowlist entry {entry:?}: {e}")))?;
        }
        if let Some(d) = &self.default_repository {
            validate_repository(d).map_err(|e| invalid(format!("default_repository: {e}")))?;
        }
        if let Some(r) = &self.default_reference {
            validate_reference(r).map_err(|e| invalid(format!("default_reference: {e}")))?;
        }
        parse_platform(&self.default_platform)
            .map_err(|e| invalid(format!("default_platform: {e}")))?;
        if self.operation.needs_repository()
            && !self.allow_any_repository
            && self.repository_allowlist.is_empty()
            && self.default_repository.is_none()
        {
            return Err(invalid(format!(
                "operation {} needs a repository: set default_repository, repository_allowlist, or allow_any_repository",
                self.operation.as_str()
            )));
        }
        if self.page_size == 0 || self.page_size > 1000 {
            return Err(invalid("page_size must be within 1..=1000".into()));
        }
        if self.max_response_bytes == 0 {
            return Err(invalid("max_response_bytes must be positive".into()));
        }
        if self.operation_timeout_ms == 0 || self.connect_timeout_ms == 0 {
            return Err(invalid("timeouts must be positive".into()));
        }
        Ok(())
    }

    /// Registry origin without a trailing slash.
    pub fn origin(&self) -> String {
        self.registry.trim().trim_end_matches('/').to_owned()
    }

    /// Registry host (for URIs, labels and audit metadata).
    pub fn host(&self) -> String {
        url::Url::parse(self.registry.trim())
            .ok()
            .and_then(|u| {
                u.host_str().map(|h| match u.port() {
                    Some(p) => format!("{h}:{p}"),
                    None => h.to_owned(),
                })
            })
            .unwrap_or_default()
    }

    /// Whether the binding may address `repository`.
    pub fn repository_admitted(&self, repository: &str) -> bool {
        if self.allow_any_repository {
            return true;
        }
        if self.default_repository.as_deref() == Some(repository) {
            return true;
        }
        self.repository_allowlist
            .iter()
            .any(|entry| match entry.strip_suffix("/*") {
                Some(prefix) => repository
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1),
                None => entry == repository,
            })
    }

    /// Resolve the repository for one call: the argument when given (and
    /// admitted), else the binding default.
    pub fn resolve_repository(&self, arg: Option<&str>) -> Result<String, String> {
        match arg.map(str::trim).filter(|s| !s.is_empty()) {
            Some(name) => {
                validate_repository(name)?;
                if !self.repository_admitted(name) {
                    return Err(format!(
                        "repository {name:?} is not admitted by this binding"
                    ));
                }
                Ok(name.to_owned())
            }
            None => self
                .default_repository
                .clone()
                .ok_or_else(|| "a `repository` argument is required".to_owned()),
        }
    }

    /// Resolve the reference for one call: the argument, the binding
    /// default, else `latest`.
    pub fn resolve_reference(&self, arg: Option<&str>) -> Result<String, String> {
        let r = arg
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .or_else(|| self.default_reference.clone())
            .unwrap_or_else(|| "latest".to_owned());
        validate_reference(&r)?;
        Ok(r)
    }
}

/// OCI distribution repository-name grammar: lowercase path components
/// joined by `/`, each `[a-z0-9]+` with `.`, `_`, `__` or `-`+ separators.
pub fn validate_repository(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 255 {
        return Err("repository name must be 1..=255 characters".into());
    }
    for component in name.split('/') {
        if !valid_component(component) {
            return Err(format!(
                "repository name {name:?} is not a valid OCI name (lowercase [a-z0-9] components separated by `/`, with `.`, `_` or `-` inside a component)"
            ));
        }
    }
    Ok(())
}

fn valid_component(c: &str) -> bool {
    let bytes = c.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !alnum(bytes[0]) || !alnum(bytes[bytes.len() - 1]) {
        return false;
    }
    let mut prev_sep = false;
    for w in bytes.windows(2) {
        let (a, b) = (w[0], w[1]);
        let sep = |x: u8| matches!(x, b'.' | b'_' | b'-');
        if !alnum(b) && !sep(b) {
            return false;
        }
        // Separators may repeat only as `__` or a run of `-`; `.` never repeats.
        if sep(a) && sep(b) {
            let ok = (a == b'_' && b == b'_' && !prev_sep) || (a == b'-' && b == b'-');
            if !ok {
                return false;
            }
            prev_sep = true;
        } else {
            prev_sep = false;
        }
    }
    true
}

/// A reference is a tag (`[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`) or a digest
/// (`<algorithm>:<hex>`).
pub fn validate_reference(reference: &str) -> Result<(), String> {
    if is_digest(reference) {
        return validate_digest(reference);
    }
    validate_tag(reference)
}

pub fn validate_tag(tag: &str) -> Result<(), String> {
    let bytes = tag.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return Err("tag must be 1..=128 characters".into());
    }
    let first_ok = bytes[0].is_ascii_alphanumeric() || bytes[0] == b'_';
    let rest_ok = bytes[1..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !first_ok || !rest_ok {
        return Err(format!("tag {tag:?} is not a valid OCI tag"));
    }
    Ok(())
}

pub fn is_digest(reference: &str) -> bool {
    reference.contains(':')
}

/// `sha256:<64 hex>` or `sha512:<128 hex>`.
pub fn validate_digest(digest: &str) -> Result<(), String> {
    let Some((algo, hex)) = digest.split_once(':') else {
        return Err(format!("digest {digest:?} is not <algorithm>:<hex>"));
    };
    let want = match algo {
        "sha256" => 64,
        "sha512" => 128,
        _ => return Err(format!("digest algorithm {algo:?} is not sha256 or sha512")),
    };
    if hex.len() != want
        || !hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(format!(
            "digest {digest:?} must carry {want} lowercase hex characters"
        ));
    }
    Ok(())
}

/// A platform selector, `os/arch[/variant]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    pub os: String,
    pub architecture: String,
    pub variant: Option<String>,
}

pub fn parse_platform(s: &str) -> Result<Platform, String> {
    let mut parts = s.trim().split('/');
    let os = parts.next().unwrap_or_default();
    let arch = parts.next().unwrap_or_default();
    let variant = parts.next();
    if os.is_empty() || arch.is_empty() || parts.next().is_some() {
        return Err(format!("platform {s:?} must be os/arch or os/arch/variant"));
    }
    Ok(Platform {
        os: os.to_owned(),
        architecture: arch.to_owned(),
        variant: variant.map(str::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec(v: Value) -> Result<OciBackendSpec, SpecError> {
        OciBackendSpec::parse(&v)
    }

    #[test]
    fn a_minimal_tags_binding_parses() {
        let s = spec(json!({
            "registry": "https://ghcr.io",
            "operation": "tags",
            "default_repository": "mcpg-dev/mcpg",
        }))
        .unwrap();
        assert_eq!(s.operation, OciOperation::Tags);
        assert_eq!(s.host(), "ghcr.io");
        assert_eq!(s.origin(), "https://ghcr.io");
        assert!(s.repository_admitted("mcpg-dev/mcpg"));
        assert!(!s.repository_admitted("mcpg-dev/other"));
    }

    #[test]
    fn plaintext_is_loopback_only_and_userinfo_is_refused() {
        assert!(spec(json!({ "registry": "http://registry.internal:5000", "operation": "catalog", "allow_any_repository": true })).is_err());
        assert!(spec(json!({ "registry": "http://localhost:5000", "operation": "catalog", "allow_any_repository": true })).is_ok());
        assert!(spec(json!({ "registry": "https://u:p@ghcr.io", "operation": "catalog", "allow_any_repository": true })).is_err());
        assert!(spec(json!({ "registry": "https://ghcr.io/?x=1", "operation": "catalog", "allow_any_repository": true })).is_err());
    }

    #[test]
    fn a_repository_operation_needs_a_way_to_pick_one() {
        let err = spec(json!({ "registry": "https://ghcr.io", "operation": "tags" }))
            .expect_err("no repository source must be refused");
        assert!(err.to_string().contains("needs a repository"), "{err}");
    }

    #[test]
    fn the_default_repository_is_admitted_beside_the_allowlist() {
        let s = spec(json!({
            "registry": "https://ghcr.io",
            "operation": "tags",
            "repository_allowlist": ["acme/*"],
            "default_repository": "other/app",
        }))
        .unwrap();
        assert!(s.repository_admitted("other/app"));
        assert!(s.repository_admitted("acme/x"));
        assert!(!s.repository_admitted("other/app2"));
        assert_eq!(s.resolve_repository(None).unwrap(), "other/app");
    }

    #[test]
    fn prefix_allowlist_admits_children_only() {
        let s = spec(json!({
            "registry": "https://ghcr.io",
            "operation": "tags",
            "repository_allowlist": ["acme/*", "solo"],
        }))
        .unwrap();
        assert!(s.repository_admitted("acme/app"));
        assert!(s.repository_admitted("acme/team/app"));
        assert!(
            !s.repository_admitted("acme"),
            "the prefix itself is not a child"
        );
        assert!(!s.repository_admitted("acme-corp/app"));
        assert!(s.repository_admitted("solo"));
        assert!(!s.repository_admitted("solo/child"));
        assert_eq!(
            s.resolve_repository(Some("evil/app")).unwrap_err(),
            "repository \"evil/app\" is not admitted by this binding"
        );
    }

    #[test]
    fn repository_grammar() {
        for ok in [
            "a",
            "a/b",
            "acme/app",
            "a.b-c_d/e__f",
            "library/ubuntu",
            "a--b",
        ] {
            assert!(validate_repository(ok).is_ok(), "{ok}");
        }
        for bad in [
            "", "A/b", "a//b", "/a", "a/", "a b", "a..b", "a___b", "-a", "a-", "a/../b", "a?b",
            "a:b", "a%2fb",
        ] {
            assert!(validate_repository(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn reference_grammar() {
        assert!(validate_reference("latest").is_ok());
        assert!(validate_reference("v1.0.0-rc.1").is_ok());
        assert!(validate_reference("_x").is_ok());
        assert!(validate_reference(&format!("sha256:{}", "a".repeat(64))).is_ok());
        assert!(validate_reference(&format!("sha512:{}", "0".repeat(128))).is_ok());
        for bad in [
            "",
            "-x",
            ".x",
            "a/b",
            "a b",
            "sha256:abc",
            &format!("sha256:{}", "A".repeat(64)),
            &format!("md5:{}", "a".repeat(32)),
            &"t".repeat(129),
        ] {
            assert!(validate_reference(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn platform_selector() {
        assert_eq!(
            parse_platform("linux/arm64/v8").unwrap(),
            Platform {
                os: "linux".into(),
                architecture: "arm64".into(),
                variant: Some("v8".into())
            }
        );
        assert!(parse_platform("linux").is_err());
        assert!(parse_platform("linux/arm64/v8/extra").is_err());
    }

    #[test]
    fn debug_never_prints_a_secret() {
        let s = spec(json!({
            "registry": "https://ghcr.io",
            "operation": "tags",
            "default_repository": "a/b",
            "auth": { "kind": "basic", "username": "u", "password": "hunter2" },
            "tls": { "ca_cert_pem": "-----BEGIN CERTIFICATE-----" },
        }))
        .unwrap();
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("hunter2"));
        assert!(!dbg.contains("BEGIN CERTIFICATE"));
        assert!(dbg.contains("***"));
    }

    #[test]
    fn nested_typos_are_refused_and_gateway_injected_keys_pass() {
        assert!(
            spec(json!({
                "registry": "https://ghcr.io", "operation": "tags", "default_repository": "a/b",
                "auth": { "kind": "basic", "username": "u", "passwrd": "x" },
            }))
            .is_err()
        );
        assert!(
            spec(json!({
                "registry": "https://ghcr.io", "operation": "tags", "default_repository": "a/b",
                "tls": { "insecure_skip_verfy": true },
            }))
            .is_err()
        );
        let s = spec(json!({
            "registry": "https://ghcr.io", "operation": "tags", "default_repository": "a/b",
            "__mcpg_secret_refs": ["cred://x/y"], "__mcpg_id_sig": "deadbeef",
        }))
        .unwrap();
        assert_eq!(s.secret_refs, vec!["cred://x/y".to_owned()]);
    }
}
