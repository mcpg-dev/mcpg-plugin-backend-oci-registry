//! The read-only distribution operations, each shaped into a stable
//! envelope.
//!
//! Every manifest and blob the plugin reads is digest-verified: the bytes
//! are hashed and compared with the digest the caller asked for, or the
//! digest the registry declared. A registry (or a redirect target) that
//! returns different bytes under a digest is reported as an error, never
//! as metadata.

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::client::{MANIFEST_ACCEPT, RegistryClient, Response};
use crate::config::{
    OciBackendSpec, OciOperation, Platform, is_digest, parse_platform, validate_digest,
};

const MEDIA_OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const MEDIA_DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
/// The tag a pre-referrers-API registry keeps a digest's referrers under:
/// `<algorithm>-<hex>`.
fn referrers_tag(digest: &str) -> String {
    digest.replacen(':', "-", 1)
}

/// Cosign's own convention predates the referrers API and is what most
/// public registries actually hold: one manifest per artefact kind under
/// `<algorithm>-<hex>.<suffix>`.
const COSIGN_TAG_SUFFIXES: &[(&str, &str)] = &[
    (".sig", "application/vnd.dev.cosign.signature"),
    (".att", "application/vnd.dev.cosign.attestation"),
    (".sbom", "application/vnd.dev.cosign.sbom"),
];

/// What one operation produced: the HTTP status of the last request, the
/// structured result, and — for a non-2xx answer — the upstream body under
/// `downstreamError`, which the gateway reads to set `is_error`.
pub struct Outcome {
    pub status: u16,
    pub ok: bool,
    pub truncated: bool,
    pub response: Value,
    pub downstream: Option<Value>,
}

/// Resolved call context: the repository / reference the operation
/// addresses, taken from the arguments or the binding defaults.
pub struct Call {
    pub repository: Option<String>,
    pub reference: Option<String>,
}

pub enum OpError {
    /// The caller's fault, or the registry's bytes not matching their digest.
    Call(String),
    /// The wire: DNS, connect, TLS, timeout, an unreadable body.
    Transport(String),
}

impl From<String> for OpError {
    fn from(s: String) -> Self {
        OpError::Transport(s)
    }
}

fn call_err<T>(m: impl Into<String>) -> Result<T, OpError> {
    Err(OpError::Call(m.into()))
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

fn arg_u64(args: &Value, key: &str) -> Result<Option<u64>, OpError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| OpError::Call(format!("`{key}` must be a non-negative integer"))),
        Some(_) => call_err(format!("`{key}` must be an integer")),
    }
}

/// Resolve the repository / reference for one call from the arguments.
pub fn resolve_call(spec: &OciBackendSpec, args: &Value) -> Result<Call, OpError> {
    let repository = if spec.operation.needs_repository() {
        Some(
            spec.resolve_repository(arg_str(args, "repository"))
                .map_err(OpError::Call)?,
        )
    } else {
        None
    };
    let reference = if spec.operation.needs_reference() {
        Some(
            spec.resolve_reference(arg_str(args, "reference"))
                .map_err(OpError::Call)?,
        )
    } else {
        None
    };
    Ok(Call {
        repository,
        reference,
    })
}

/// Run the binding's operation.
pub async fn run(
    client: &RegistryClient,
    spec: &OciBackendSpec,
    call: &Call,
    args: &Value,
) -> Result<Outcome, OpError> {
    match spec.operation {
        OciOperation::Catalog => catalog(client, spec, args).await,
        OciOperation::Tags => {
            tags(
                client,
                spec,
                call.repository.as_deref().unwrap_or_default(),
                args,
            )
            .await
        }
        OciOperation::Resolve => {
            resolve(
                client,
                spec,
                call.repository.as_deref().unwrap_or_default(),
                call.reference.as_deref().unwrap_or_default(),
            )
            .await
        }
        OciOperation::Manifest => {
            manifest(
                client,
                spec,
                call.repository.as_deref().unwrap_or_default(),
                call.reference.as_deref().unwrap_or_default(),
            )
            .await
        }
        OciOperation::ImageConfig => {
            image_config(
                client,
                spec,
                call.repository.as_deref().unwrap_or_default(),
                call.reference.as_deref().unwrap_or_default(),
                args,
            )
            .await
        }
        OciOperation::Referrers => {
            referrers(
                client,
                spec,
                call.repository.as_deref().unwrap_or_default(),
                call.reference.as_deref().unwrap_or_default(),
                args,
            )
            .await
        }
    }
}

fn scope_for(repository: &str) -> String {
    format!("repository:{repository}:pull")
}

fn paging_query(spec: &OciBackendSpec, args: &Value) -> Result<String, OpError> {
    let n = arg_u64(args, "n")?.unwrap_or(spec.page_size).clamp(1, 1000);
    let mut q = format!("n={n}");
    if let Some(last) = arg_str(args, "last")
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        // `last` is a name or tag the registry itself returned; it still has
        // to be a valid one before it is spliced into a query.
        if last.len() > 255
            || !last
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
        {
            return call_err("`last` is not a valid repository name or tag");
        }
        q.push_str("&last=");
        q.push_str(&urlencoding_encode(last));
    }
    Ok(q)
}

/// Percent-encode the characters a name or tag may carry that a query value
/// may not (`/` is the only one the grammar admits).
fn urlencoding_encode(s: &str) -> String {
    s.replace('/', "%2F")
}

/// The `last` value of the `rel="next"` Link a paginated listing carries.
pub fn next_page_cursor(resp: &Response) -> Option<String> {
    let link = resp.header("link")?;
    for part in link.split(',') {
        let part = part.trim();
        if !part.contains("rel=\"next\"") && !part.contains("rel=next") {
            continue;
        }
        let target = part.split_once('>')?.0.trim_start_matches('<');
        let url = url::Url::parse(target)
            .or_else(|_| url::Url::parse(&format!("https://registry.invalid{target}")))
            .ok()?;
        return url
            .query_pairs()
            .find(|(k, _)| k == "last")
            .map(|(_, v)| v.into_owned());
    }
    None
}

fn upstream_failure(resp: &Response) -> Outcome {
    let body = resp
        .json()
        .unwrap_or_else(|| json!(String::from_utf8_lossy(&resp.body).into_owned()));
    Outcome {
        status: resp.status,
        ok: false,
        truncated: false,
        response: Value::Null,
        downstream: Some(json!({ "statusCode": resp.status, "body": body })),
    }
}

fn success(status: u16, truncated: bool, response: Value) -> Outcome {
    Outcome {
        status,
        ok: true,
        truncated,
        response,
        downstream: None,
    }
}

async fn catalog(
    client: &RegistryClient,
    spec: &OciBackendSpec,
    args: &Value,
) -> Result<Outcome, OpError> {
    let path = format!("/v2/_catalog?{}", paging_query(spec, args)?);
    let resp = client
        .get(&path, "application/json", "registry:catalog:*")
        .await?;
    if resp.status != 200 {
        return Ok(upstream_failure(&resp));
    }
    let body = resp
        .json()
        .ok_or_else(|| OpError::Transport("catalog body is not JSON".into()))?;
    let all: Vec<String> = body
        .get("repositories")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let repositories: Vec<String> = all
        .into_iter()
        .filter(|r| spec.repository_admitted(r))
        .collect();
    Ok(success(
        resp.status,
        resp.truncated,
        json!({
            "repositories": repositories,
            "next_last": next_page_cursor(&resp),
        }),
    ))
}

async fn tags(
    client: &RegistryClient,
    spec: &OciBackendSpec,
    repository: &str,
    args: &Value,
) -> Result<Outcome, OpError> {
    let path = format!("/v2/{repository}/tags/list?{}", paging_query(spec, args)?);
    let resp = client
        .get(&path, "application/json", &scope_for(repository))
        .await?;
    if resp.status != 200 {
        return Ok(upstream_failure(&resp));
    }
    let body = resp
        .json()
        .ok_or_else(|| OpError::Transport("tags body is not JSON".into()))?;
    let tags: Vec<String> = body
        .get("tags")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    Ok(success(
        resp.status,
        resp.truncated,
        json!({
            "repository": repository,
            "tags": tags,
            "next_last": next_page_cursor(&resp),
        }),
    ))
}

/// A verified manifest read: bytes, their digest, and the media type.
pub struct VerifiedManifest {
    pub digest: String,
    pub media_type: String,
    pub size: usize,
    pub body: Value,
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Fetch a manifest and verify its bytes against the digest requested (when
/// the reference is one) and the digest declared (when the registry sends
/// `Docker-Content-Digest`).
pub async fn fetch_manifest(
    client: &RegistryClient,
    repository: &str,
    reference: &str,
) -> Result<Result<VerifiedManifest, Response>, OpError> {
    let path = format!("/v2/{repository}/manifests/{reference}");
    let resp = client
        .get(&path, MANIFEST_ACCEPT, &scope_for(repository))
        .await?;
    if resp.status != 200 {
        return Ok(Err(resp));
    }
    if resp.truncated {
        return call_err("manifest exceeds max_response_bytes");
    }
    let digest = sha256_hex(&resp.body);
    if is_digest(reference) && reference.starts_with("sha256:") && reference != digest {
        return call_err(format!(
            "manifest bytes hash to {digest}, not the requested {reference}"
        ));
    }
    if let Some(declared) = resp.header("docker-content-digest")
        && declared.starts_with("sha256:")
        && declared != digest
    {
        return call_err(format!(
            "registry declared digest {declared} but the manifest bytes hash to {digest}"
        ));
    }
    let body: Value = serde_json::from_slice(&resp.body)
        .map_err(|e| OpError::Call(format!("manifest is not JSON: {e}")))?;
    let media_type = resp
        .header("content-type")
        .map(|ct| ct.split(';').next().unwrap_or(ct).trim().to_owned())
        .or_else(|| {
            body.get("mediaType")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default();
    Ok(Ok(VerifiedManifest {
        digest,
        media_type,
        size: resp.body.len(),
        body,
    }))
}

fn is_index(media_type: &str, body: &Value) -> bool {
    media_type == MEDIA_OCI_INDEX
        || media_type == MEDIA_DOCKER_LIST
        || (body.get("manifests").is_some() && body.get("layers").is_none())
}

/// The platform entries of an index, flattened for a reader.
fn index_platforms(body: &Value) -> Vec<Value> {
    body.get("manifests")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .map(|m| {
                    json!({
                        "digest": m.get("digest"),
                        "media_type": m.get("mediaType"),
                        "size": m.get("size"),
                        "os": m.pointer("/platform/os"),
                        "architecture": m.pointer("/platform/architecture"),
                        "variant": m.pointer("/platform/variant"),
                        "artifact_type": m.get("artifactType"),
                        "annotations": m.get("annotations"),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

async fn resolve(
    client: &RegistryClient,
    spec: &OciBackendSpec,
    repository: &str,
    reference: &str,
) -> Result<Outcome, OpError> {
    let _ = spec;
    let path = format!("/v2/{repository}/manifests/{reference}");
    let head = client
        .head(&path, MANIFEST_ACCEPT, &scope_for(repository))
        .await?;
    let mut media_type = head
        .header("content-type")
        .map(|ct| ct.split(';').next().unwrap_or(ct).trim().to_owned());
    let mut size = head
        .header("content-length")
        .and_then(|l| l.parse::<u64>().ok());
    let status;
    let digest = match (head.status, head.header("docker-content-digest")) {
        (200, Some(d)) if validate_digest(d).is_ok() => {
            status = 200;
            d.to_owned()
        }
        // Registries that omit the header on HEAD (or refuse HEAD) still
        // answer a GET, and the bytes carry their own digest.
        _ => match fetch_manifest(client, repository, reference).await? {
            Ok(m) => {
                status = 200;
                media_type = Some(m.media_type.clone());
                size = Some(m.size as u64);
                m.digest
            }
            Err(resp) => return Ok(upstream_failure(&resp)),
        },
    };
    Ok(success(
        status,
        false,
        json!({
            "repository": repository,
            "reference": reference,
            "digest": digest,
            "media_type": media_type,
            "size": size,
        }),
    ))
}

async fn manifest(
    client: &RegistryClient,
    spec: &OciBackendSpec,
    repository: &str,
    reference: &str,
) -> Result<Outcome, OpError> {
    let _ = spec;
    let m = match fetch_manifest(client, repository, reference).await? {
        Ok(m) => m,
        Err(resp) => return Ok(upstream_failure(&resp)),
    };
    let index = is_index(&m.media_type, &m.body);
    let mut out = Map::new();
    out.insert("repository".into(), json!(repository));
    out.insert("reference".into(), json!(reference));
    out.insert("digest".into(), json!(m.digest));
    out.insert("media_type".into(), json!(m.media_type));
    out.insert("size".into(), json!(m.size));
    out.insert("is_index".into(), json!(index));
    if index {
        out.insert("platforms".into(), Value::Array(index_platforms(&m.body)));
    } else {
        out.insert(
            "config_digest".into(),
            m.body
                .pointer("/config/digest")
                .cloned()
                .unwrap_or(Value::Null),
        );
        out.insert("layers".into(), layers_of(&m.body));
    }
    if let Some(a) = m.body.get("annotations") {
        out.insert("annotations".into(), a.clone());
    }
    if let Some(a) = m.body.get("artifactType") {
        out.insert("artifact_type".into(), a.clone());
    }
    out.insert("manifest".into(), m.body);
    Ok(success(200, false, Value::Object(out)))
}

fn layers_of(manifest: &Value) -> Value {
    manifest
        .get("layers")
        .and_then(Value::as_array)
        .map(|layers| {
            Value::Array(
                layers
                    .iter()
                    .map(|l| {
                        json!({
                            "digest": l.get("digest"),
                            "media_type": l.get("mediaType"),
                            "size": l.get("size"),
                        })
                    })
                    .collect(),
            )
        })
        .unwrap_or_else(|| json!([]))
}

fn platform_matches(entry: &Value, want: &Platform) -> bool {
    let os = entry.pointer("/platform/os").and_then(Value::as_str);
    let arch = entry
        .pointer("/platform/architecture")
        .and_then(Value::as_str);
    let variant = entry.pointer("/platform/variant").and_then(Value::as_str);
    os == Some(want.os.as_str())
        && arch == Some(want.architecture.as_str())
        && match &want.variant {
            Some(v) => variant == Some(v.as_str()),
            None => true,
        }
}

async fn image_config(
    client: &RegistryClient,
    spec: &OciBackendSpec,
    repository: &str,
    reference: &str,
    args: &Value,
) -> Result<Outcome, OpError> {
    let want = parse_platform(arg_str(args, "platform").unwrap_or(&spec.default_platform))
        .map_err(OpError::Call)?;
    let top = match fetch_manifest(client, repository, reference).await? {
        Ok(m) => m,
        Err(resp) => return Ok(upstream_failure(&resp)),
    };
    // A multi-platform image is an index; pick the platform manifest and
    // read it by digest, which the fetch verifies.
    let (image, index_digest) = if is_index(&top.media_type, &top.body) {
        let entries = top
            .body
            .get("manifests")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let Some(chosen) = entries.iter().find(|e| platform_matches(e, &want)) else {
            let available: Vec<String> = entries
                .iter()
                .filter_map(|e| {
                    let os = e.pointer("/platform/os")?.as_str()?;
                    let arch = e.pointer("/platform/architecture")?.as_str()?;
                    Some(
                        match e.pointer("/platform/variant").and_then(Value::as_str) {
                            Some(v) => format!("{os}/{arch}/{v}"),
                            None => format!("{os}/{arch}"),
                        },
                    )
                })
                .collect();
            return call_err(format!(
                "no manifest for platform {}/{}{} in the index; available: {}",
                want.os,
                want.architecture,
                want.variant
                    .as_ref()
                    .map(|v| format!("/{v}"))
                    .unwrap_or_default(),
                if available.is_empty() {
                    "none".to_owned()
                } else {
                    available.join(", ")
                }
            ));
        };
        let digest = chosen
            .get("digest")
            .and_then(Value::as_str)
            .ok_or_else(|| OpError::Call("index entry has no digest".into()))?;
        validate_digest(digest).map_err(OpError::Call)?;
        match fetch_manifest(client, repository, digest).await? {
            Ok(m) => (m, Some(top.digest.clone())),
            Err(resp) => return Ok(upstream_failure(&resp)),
        }
    } else {
        (top, None)
    };

    let config_digest = image
        .body
        .pointer("/config/digest")
        .and_then(Value::as_str)
        .ok_or_else(|| OpError::Call("manifest has no config descriptor".into()))?
        .to_owned();
    validate_digest(&config_digest).map_err(OpError::Call)?;
    let blob_path = format!("/v2/{repository}/blobs/{config_digest}");
    let resp = client
        .get(
            &blob_path,
            "application/octet-stream, application/json",
            &scope_for(repository),
        )
        .await?;
    if resp.status != 200 {
        return Ok(upstream_failure(&resp));
    }
    if resp.truncated {
        return call_err("image config exceeds max_response_bytes");
    }
    let got = sha256_hex(&resp.body);
    if config_digest.starts_with("sha256:") && got != config_digest {
        return call_err(format!(
            "config blob bytes hash to {got}, not the manifest's {config_digest}"
        ));
    }
    let config: Value = serde_json::from_slice(&resp.body)
        .map_err(|e| OpError::Call(format!("image config is not JSON: {e}")))?;

    let layers = layers_of(&image.body);
    let total_size: u64 = layers
        .as_array()
        .map(|ls| {
            ls.iter()
                .filter_map(|l| l.get("size").and_then(Value::as_u64))
                .sum()
        })
        .unwrap_or(0);
    let cfg = config.get("config").cloned().unwrap_or(Value::Null);
    let mut out = Map::new();
    out.insert("repository".into(), json!(repository));
    out.insert("reference".into(), json!(reference));
    out.insert("digest".into(), json!(image.digest));
    out.insert("index_digest".into(), json!(index_digest));
    out.insert("media_type".into(), json!(image.media_type));
    out.insert("config_digest".into(), json!(config_digest));
    out.insert(
        "platform".into(),
        json!({
            "os": config.get("os"),
            "architecture": config.get("architecture"),
            "variant": config.get("variant"),
            "os_version": config.get("os.version"),
        }),
    );
    out.insert(
        "created".into(),
        config.get("created").cloned().unwrap_or(Value::Null),
    );
    out.insert(
        "author".into(),
        config.get("author").cloned().unwrap_or(Value::Null),
    );
    out.insert(
        "labels".into(),
        cfg.get("Labels").cloned().unwrap_or(json!({})),
    );
    out.insert("env".into(), cfg.get("Env").cloned().unwrap_or(json!([])));
    out.insert(
        "entrypoint".into(),
        cfg.get("Entrypoint").cloned().unwrap_or(Value::Null),
    );
    out.insert("cmd".into(), cfg.get("Cmd").cloned().unwrap_or(Value::Null));
    out.insert(
        "working_dir".into(),
        cfg.get("WorkingDir").cloned().unwrap_or(Value::Null),
    );
    out.insert(
        "user".into(),
        cfg.get("User").cloned().unwrap_or(Value::Null),
    );
    out.insert(
        "exposed_ports".into(),
        cfg.get("ExposedPorts").cloned().unwrap_or(Value::Null),
    );
    out.insert(
        "volumes".into(),
        cfg.get("Volumes").cloned().unwrap_or(Value::Null),
    );
    out.insert(
        "stop_signal".into(),
        cfg.get("StopSignal").cloned().unwrap_or(Value::Null),
    );
    out.insert("layers".into(), layers);
    out.insert("total_size".into(), json!(total_size));
    out.insert(
        "annotations".into(),
        image.body.get("annotations").cloned().unwrap_or(json!({})),
    );
    out.insert(
        "history_entries".into(),
        json!(
            config
                .get("history")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0)
        ),
    );
    out.insert("config".into(), config);
    Ok(success(200, false, Value::Object(out)))
}

async fn referrers(
    client: &RegistryClient,
    spec: &OciBackendSpec,
    repository: &str,
    reference: &str,
    args: &Value,
) -> Result<Outcome, OpError> {
    let _ = spec;
    // The subject must be a digest; a tag is resolved first.
    let subject = if is_digest(reference) {
        reference.to_owned()
    } else {
        let head = client
            .head(
                &format!("/v2/{repository}/manifests/{reference}"),
                MANIFEST_ACCEPT,
                &scope_for(repository),
            )
            .await?;
        match (head.status, head.header("docker-content-digest")) {
            (200, Some(d)) if validate_digest(d).is_ok() => d.to_owned(),
            _ => match fetch_manifest(client, repository, reference).await? {
                Ok(m) => m.digest,
                Err(resp) => return Ok(upstream_failure(&resp)),
            },
        }
    };
    let artifact_type = arg_str(args, "artifact_type")
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let mut path = format!("/v2/{repository}/referrers/{subject}");
    if let Some(at) = artifact_type {
        if !at
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'/' | b'+' | b'-' | b'_'))
        {
            return call_err("`artifact_type` is not a valid media type");
        }
        path.push_str("?artifactType=");
        path.push_str(&at.replace('/', "%2F").replace('+', "%2B"));
    }
    let resp = client
        .get(&path, MEDIA_OCI_INDEX, &scope_for(repository))
        .await?;
    let (mut entries, source, status) = if resp.status == 200 {
        let body = resp
            .json()
            .ok_or_else(|| OpError::Transport("referrers body is not JSON".into()))?;
        (index_platforms(&body), "referrers_api", 200)
    } else if resp.status == 404 {
        // Pre-1.1 registries: the referrers live in an index tagged
        // `<algorithm>-<hex>`; absent tag means no referrers there.
        match fetch_manifest(client, repository, &referrers_tag(&subject)).await? {
            Ok(m) => {
                let mut entries = index_platforms(&m.body);
                if let Some(at) = artifact_type {
                    entries.retain(|e| e.get("artifact_type").and_then(Value::as_str) == Some(at));
                }
                (entries, "tag_schema", 200)
            }
            Err(r) if r.status == 404 => (Vec::new(), "tag_schema", 200),
            Err(r) => return Ok(upstream_failure(&r)),
        }
    } else {
        return Ok(upstream_failure(&resp));
    };
    // Cosign's tagged artefacts sit beside the image on every registry;
    // the referrers API (where present) indexes them too, so they are only
    // probed on the fallback path.
    if source == "tag_schema" {
        for (suffix, kind) in COSIGN_TAG_SUFFIXES {
            if artifact_type.is_some_and(|at| at != *kind) {
                continue;
            }
            let tag = format!("{}{suffix}", referrers_tag(&subject));
            match fetch_manifest(client, repository, &tag).await? {
                Ok(m) => entries.push(json!({
                    "digest": m.digest,
                    "media_type": m.media_type,
                    "size": m.size,
                    "artifact_type": kind,
                    "tag": tag,
                    "layers": layers_of(&m.body),
                    "annotations": m.body.get("annotations"),
                })),
                Err(r) if r.status == 404 => {}
                Err(r) => return Ok(upstream_failure(&r)),
            }
        }
    }
    Ok(success(
        status,
        false,
        json!({
            "repository": repository,
            "subject": subject,
            "referrers": entries,
            "source": source,
        }),
    ))
}

/// Tool input schema for the binding's operation. `repository` is required
/// only when the binding has no default.
pub fn input_schema(spec: &OciBackendSpec) -> Value {
    let mut props = Map::new();
    let mut required = Vec::new();
    if spec.operation.needs_repository() {
        props.insert(
            "repository".into(),
            json!({
                "type": "string",
                "description": "Repository name (e.g. `org/app`). Must be one the binding admits.",
            }),
        );
        if spec.default_repository.is_none() {
            required.push(json!("repository"));
        }
    }
    if spec.operation.needs_reference() {
        props.insert(
            "reference".into(),
            json!({
                "type": "string",
                "description": "A tag (e.g. `latest`, `v1.2.3`) or a digest (`sha256:…`). Defaults to the binding's default_reference, else `latest`.",
            }),
        );
    }
    match spec.operation {
        OciOperation::Catalog | OciOperation::Tags => {
            props.insert("n".into(), json!({ "type": "integer", "minimum": 1, "maximum": 1000, "description": "Page size." }));
            props.insert("last".into(), json!({ "type": "string", "description": "Paging cursor: the `next_last` of the previous page." }));
        }
        OciOperation::ImageConfig => {
            props.insert(
                "platform".into(),
                json!({ "type": "string", "description": "`os/arch[/variant]` to select from a multi-platform image (default from the binding, `linux/amd64` unless set)." }),
            );
        }
        OciOperation::Referrers => {
            props.insert(
                "artifact_type".into(),
                json!({ "type": "string", "description": "Only referrers of this artifactType. Cosign-tagged artefacts report `application/vnd.dev.cosign.signature`, `.attestation` or `.sbom`." }),
            );
        }
        _ => {}
    }
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": Value::Object(props),
        "required": required,
        "additionalProperties": false,
    })
}

/// JSON Schema for the envelope every operation returns. `response` is
/// operation-specific and stays open.
pub fn result_envelope_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "operation": { "type": "string" },
            "registry": { "type": "string" },
            "repository": { "type": ["string", "null"] },
            "reference": { "type": ["string", "null"] },
            "statusCode": { "type": "integer" },
            "ok": { "type": "boolean" },
            "truncated": { "type": "boolean" },
            "response": {},
            "downstreamError": { "type": ["object", "null"] },
            "__mcpg_verbatim_result": { "type": "object" }
        },
        "additionalProperties": true
    })
}

/// Shape an outcome into the envelope.
pub fn envelope(spec: &OciBackendSpec, call: &Call, out: &Outcome) -> Value {
    let mut env = Map::new();
    env.insert("operation".into(), json!(spec.operation.as_str()));
    env.insert("registry".into(), json!(spec.host()));
    env.insert("repository".into(), json!(call.repository));
    env.insert("reference".into(), json!(call.reference));
    env.insert("statusCode".into(), json!(out.status));
    env.insert("ok".into(), json!(out.ok));
    env.insert("truncated".into(), json!(out.truncated));
    if out.ok {
        env.insert("response".into(), out.response.clone());
    }
    if let Some(d) = &out.downstream {
        env.insert("downstreamError".into(), d.clone());
    }
    Value::Object(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp_with(link: Option<&str>) -> Response {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(l) = link {
            headers.insert("link", reqwest::header::HeaderValue::from_str(l).unwrap());
        }
        Response {
            status: 200,
            headers,
            body: Vec::new(),
            truncated: false,
        }
    }

    #[test]
    fn the_next_page_cursor_comes_from_the_link_header() {
        assert_eq!(
            next_page_cursor(&resp_with(Some(
                r#"</v2/_catalog?n=100&last=acme%2Fapp>; rel="next""#
            ))),
            Some("acme/app".into())
        );
        assert_eq!(
            next_page_cursor(&resp_with(Some(
                r#"<https://ghcr.io/v2/a/b/tags/list?last=v1&n=2>; rel="next""#
            ))),
            Some("v1".into())
        );
        assert_eq!(
            next_page_cursor(&resp_with(Some(r#"</x>; rel="prev""#))),
            None
        );
        assert_eq!(next_page_cursor(&resp_with(None)), None);
    }

    #[test]
    fn the_referrers_tag_schema_is_algorithm_dash_hex() {
        assert_eq!(referrers_tag("sha256:abc"), "sha256-abc");
    }

    #[test]
    fn index_detection_uses_media_type_then_shape() {
        assert!(is_index(MEDIA_OCI_INDEX, &json!({})));
        assert!(is_index(MEDIA_DOCKER_LIST, &json!({})));
        assert!(is_index("", &json!({ "manifests": [] })));
        assert!(!is_index(
            "application/vnd.oci.image.manifest.v1+json",
            &json!({ "layers": [] })
        ));
    }

    #[test]
    fn platform_selection_honours_the_variant_only_when_asked() {
        let entry =
            json!({ "platform": { "os": "linux", "architecture": "arm64", "variant": "v8" } });
        assert!(platform_matches(
            &entry,
            &parse_platform("linux/arm64").unwrap()
        ));
        assert!(platform_matches(
            &entry,
            &parse_platform("linux/arm64/v8").unwrap()
        ));
        assert!(!platform_matches(
            &entry,
            &parse_platform("linux/arm64/v7").unwrap()
        ));
        assert!(!platform_matches(
            &entry,
            &parse_platform("linux/amd64").unwrap()
        ));
    }

    #[test]
    fn the_input_schema_requires_a_repository_only_without_a_default() {
        let with_default: OciBackendSpec = serde_json::from_value(json!({
            "registry": "https://ghcr.io", "operation": "tags", "default_repository": "a/b",
        }))
        .unwrap();
        assert_eq!(input_schema(&with_default)["required"], json!([]));
        let without: OciBackendSpec = serde_json::from_value(json!({
            "registry": "https://ghcr.io", "operation": "image_config", "repository_allowlist": ["a/*"],
        }))
        .unwrap();
        let schema = input_schema(&without);
        assert_eq!(schema["required"], json!(["repository"]));
        assert!(schema["properties"]["platform"].is_object());
        assert!(schema["properties"]["n"].is_null());
    }

    #[test]
    fn paging_refuses_a_cursor_that_is_not_a_name() {
        let spec: OciBackendSpec = serde_json::from_value(json!({
            "registry": "https://ghcr.io", "operation": "catalog", "allow_any_repository": true,
        }))
        .unwrap();
        assert_eq!(paging_query(&spec, &json!({})).ok().unwrap(), "n=100");
        assert_eq!(
            paging_query(&spec, &json!({ "n": 5000, "last": "acme/app" }))
                .ok()
                .unwrap(),
            "n=1000&last=acme%2Fapp"
        );
        assert!(matches!(
            paging_query(&spec, &json!({ "last": "a b" })),
            Err(OpError::Call(_))
        ));
        assert!(matches!(
            paging_query(&spec, &json!({ "n": "ten" })),
            Err(OpError::Call(_))
        ));
    }
}
