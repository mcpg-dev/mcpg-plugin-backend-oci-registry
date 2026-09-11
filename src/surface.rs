//! MCP surface shaping for resource bindings.
//!
//! A binding is a tool by default; the operator may instead place it under
//! `mcp.capabilities.resources[]` / `resource_templates[]`. The gateway
//! routes those reads to the same `execute()` path but applies a strict
//! decoder over the response body — `{contents:[…]}` for `resources/read`.
//! Only successful results are reshaped; a failed operation keeps the tool
//! envelope (carrying `downstreamError`) on every surface, so the decoder
//! sees a clean error rather than an invalid `{contents}` body.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Which MCP surface a binding serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    /// Tool surface — the operation envelope as-is.
    #[default]
    Tool,
    /// `resources/read` surface — `{contents:[{uri,text,mimeType}]}`.
    Resource,
}

impl Surface {
    pub fn as_str(self) -> &'static str {
        match self {
            Surface::Tool => "tool",
            Surface::Resource => "resource",
        }
    }
}

/// Resolve the resource URI for a `resources/read`: a static binding `uri`
/// wins, otherwise the gateway-supplied `uri` argument.
pub fn resolve_resource_uri<'a>(
    static_uri: Option<&'a str>,
    arguments: &'a Value,
) -> Option<&'a str> {
    if let Some(u) = static_uri
        && !u.trim().is_empty()
    {
        return Some(u);
    }
    arguments
        .get("uri")
        .and_then(Value::as_str)
        .filter(|u| !u.trim().is_empty())
}

/// Wrap a result body into the `resources/read` contract body — one content
/// entry whose `text` is the JSON-serialized result.
pub fn resource_contents_body(uri: &str, body: &Value) -> Value {
    let text = serde_json::to_string(body).unwrap_or_else(|_| "null".to_owned());
    json!({
        "contents": [
            { "uri": uri, "text": text, "mimeType": "application/json" }
        ]
    })
}

/// Parse an `oci://<host>/<repository>[:<tag>|@<digest>]` resource URI into
/// `(repository, reference)`. The host is checked against the binding's
/// registry by the caller; a URI without a reference yields `None` for it.
pub fn parse_oci_uri(uri: &str) -> Option<(String, String, Option<String>)> {
    let rest = uri.strip_prefix("oci://")?;
    let (host, path) = rest.split_once('/')?;
    if host.is_empty() || path.is_empty() {
        return None;
    }
    if let Some((repo, digest)) = path.split_once('@') {
        return Some((host.to_owned(), repo.to_owned(), Some(digest.to_owned())));
    }
    // The host (with any port) is already split off, and a repository name
    // cannot contain `:`, so a remaining `:` can only separate the tag.
    match path.rsplit_once(':') {
        Some((repo, tag)) => Some((host.to_owned(), repo.to_owned(), Some(tag.to_owned()))),
        None => Some((host.to_owned(), path.to_owned(), None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_body_is_one_json_content_entry() {
        let body = resource_contents_body("oci://ghcr.io/a/b:latest", &json!({ "x": 1 }));
        assert_eq!(body["contents"][0]["uri"], "oci://ghcr.io/a/b:latest");
        assert_eq!(body["contents"][0]["mimeType"], "application/json");
        assert_eq!(body["contents"][0]["text"], "{\"x\":1}");
    }

    #[test]
    fn static_uri_wins_over_the_argument() {
        let args = json!({ "uri": "oci://ghcr.io/a/b:1" });
        assert_eq!(
            resolve_resource_uri(Some("oci://x/y:z"), &args),
            Some("oci://x/y:z")
        );
        assert_eq!(
            resolve_resource_uri(Some("  "), &args),
            Some("oci://ghcr.io/a/b:1")
        );
        assert_eq!(resolve_resource_uri(None, &json!({})), None);
    }

    #[test]
    fn oci_uris_split_into_repository_and_reference() {
        assert_eq!(
            parse_oci_uri("oci://ghcr.io/mcpg-dev/mcpg:1.0.0"),
            Some((
                "ghcr.io".into(),
                "mcpg-dev/mcpg".into(),
                Some("1.0.0".into())
            ))
        );
        assert_eq!(
            parse_oci_uri("oci://localhost:5000/lib/app@sha256:abc"),
            Some((
                "localhost:5000".into(),
                "lib/app".into(),
                Some("sha256:abc".into())
            ))
        );
        assert_eq!(
            parse_oci_uri("oci://ghcr.io/mcpg-dev/mcpg"),
            Some(("ghcr.io".into(), "mcpg-dev/mcpg".into(), None))
        );
        assert_eq!(parse_oci_uri("https://ghcr.io/a"), None);
        assert_eq!(parse_oci_uri("oci://ghcr.io"), None);
        assert_eq!(parse_oci_uri("oci:///a/b"), None);
    }
}
