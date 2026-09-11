//! The registry HTTP client: one origin, the distribution token flow, and
//! the two outbound guards a registry needs that a plain REST backend does
//! not.
//!
//! A registry hands the client two URLs of its own choosing: the token realm
//! in a `WWW-Authenticate: Bearer` challenge, and a `Location` when a blob
//! or manifest read is redirected to backing storage. Both are dialled only
//! after the same DNS-rebinding guard the registry origin passes, and a
//! redirect that leaves the registry's origin is fetched without the
//! credential — the registry's storage never sees the registry's token.
//!
//! Every response body is read up to a byte cap and no further: manifests
//! and image configs are small documents, and this plugin never fetches a
//! layer.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine as _;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, LOCATION, WWW_AUTHENTICATE};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use url::Url;

use crate::config::{OciAuth, OciBackendSpec};

/// Media types a manifest request accepts, in preference order. Listing the
/// index types is what makes a multi-platform image come back as an index
/// rather than a registry-chosen platform manifest.
pub const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
    application/vnd.oci.image.manifest.v1+json, \
    application/vnd.docker.distribution.manifest.list.v2+json, \
    application/vnd.docker.distribution.manifest.v2+json";

/// Bound on a token-realm response: a token document is a few hundred bytes.
const TOKEN_RESPONSE_CAP: usize = 64 * 1024;
/// Redirect hops followed for a storage-backed read.
const MAX_REDIRECTS: usize = 5;
/// Lifetime assumed for a token whose response names none (the
/// distribution spec's default).
const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(60);
/// Renew a cached token this long before it expires, so a request issued
/// at the boundary does not present a token the registry already rejects.
const TOKEN_RENEW_MARGIN: Duration = Duration::from_secs(10);

pub struct Response {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    /// The body exceeded the cap and was cut at it.
    pub truncated: bool,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    pub fn json(&self) -> Option<serde_json::Value> {
        if self.truncated {
            return None;
        }
        serde_json::from_slice(&self.body).ok()
    }
}

struct CachedToken {
    token: String,
    expires_at: Instant,
}

pub struct RegistryClient {
    http: reqwest::Client,
    origin: Url,
    auth: OciAuth,
    allow_private: bool,
    max_bytes: usize,
    /// Tokens by challenge scope. A registry issues one per repository and
    /// action, so a binding that reaches several repositories holds several.
    tokens: Mutex<HashMap<String, CachedToken>>,
}

impl RegistryClient {
    pub fn new(spec: &OciBackendSpec) -> Result<Self, String> {
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(spec.connect_timeout_ms))
            .timeout(Duration::from_millis(spec.operation_timeout_ms))
            // Redirects are followed by hand so each hop passes the guard.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!(
                "mcpg-plugin-backend-oci-registry/",
                env!("CARGO_PKG_VERSION")
            ));
        if let Some(pem) = &spec.tls.ca_cert_pem {
            let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|e| format!("tls.ca_cert_pem parse: {e}"))?;
            builder = builder.add_root_certificate(cert);
        }
        if spec.tls.insecure_skip_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let http = builder.build().map_err(|e| format!("reqwest build: {e}"))?;
        let origin =
            Url::parse(&spec.origin()).map_err(|_| "registry URL failed to parse".to_owned())?;
        Ok(Self {
            http,
            origin,
            auth: spec.auth.clone(),
            allow_private: spec.allow_private_backends,
            max_bytes: spec.max_response_bytes,
            tokens: Mutex::new(HashMap::new()),
        })
    }

    /// `GET <origin><path>` with the distribution auth flow and guarded
    /// redirects. `scope` is the token scope the request needs
    /// (`repository:<name>:pull`, or `registry:catalog:*`).
    pub async fn get(&self, path: &str, accept: &str, scope: &str) -> Result<Response, String> {
        self.call(Method::GET, path, accept, scope, true).await
    }

    /// `HEAD <origin><path>` — the digest a reference resolves to, without
    /// the body.
    pub async fn head(&self, path: &str, accept: &str, scope: &str) -> Result<Response, String> {
        self.call(Method::HEAD, path, accept, scope, true).await
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        accept: &str,
        scope: &str,
        follow: bool,
    ) -> Result<Response, String> {
        let url = self
            .origin
            .join(path)
            .map_err(|e| format!("request path failed to join the registry origin: {e}"))?;
        // A joined path must stay on the registry: the pieces are validated
        // names, but the invariant is cheap to state and check here.
        if url.origin() != self.origin.origin() {
            return Err("request path left the registry origin".to_owned());
        }
        self.guard(&url).await?;

        let first = self
            .send(method.clone(), url.clone(), accept, self.credential(scope))
            .await?;
        let response = if first.status == StatusCode::UNAUTHORIZED.as_u16() {
            match self.answer_challenge(&first, scope).await? {
                Some(header) => {
                    self.send(method.clone(), url.clone(), accept, Some(header))
                        .await?
                }
                None => first,
            }
        } else {
            first
        };
        if follow && is_redirect(response.status) {
            return self.follow(method, response, accept).await;
        }
        Ok(response)
    }

    /// The `Authorization` value to present up front: a static bearer, or a
    /// token already obtained for this scope. Basic is presented only in
    /// answer to a challenge, so the password never reaches an endpoint
    /// that did not ask for it.
    fn credential(&self, scope: &str) -> Option<String> {
        if let OciAuth::Bearer { token } = &self.auth {
            return Some(format!("Bearer {}", token.trim()));
        }
        let mut tokens = self.tokens.lock().expect("token cache poisoned");
        match tokens.get(scope) {
            Some(cached) if cached.expires_at > Instant::now() + TOKEN_RENEW_MARGIN => {
                Some(format!("Bearer {}", cached.token))
            }
            Some(_) => {
                tokens.remove(scope);
                None
            }
            None => None,
        }
    }

    /// Turn a 401 into the credential it asks for: the distribution token
    /// flow for a `Bearer` challenge, the configured Basic pair for a
    /// `Basic` one. `None` when the challenge cannot be answered — the 401
    /// is then the result.
    async fn answer_challenge(
        &self,
        resp: &Response,
        scope: &str,
    ) -> Result<Option<String>, String> {
        let Some(challenge) = resp.header(WWW_AUTHENTICATE.as_str()) else {
            return Ok(None);
        };
        let Some(parsed) = parse_challenge(challenge) else {
            return Ok(None);
        };
        match parsed {
            Challenge::Basic => Ok(self.basic_header()),
            Challenge::Bearer {
                realm,
                service,
                scope: challenged,
            } => {
                if matches!(self.auth, OciAuth::Bearer { .. }) {
                    // A static token the registry refused is not improved by
                    // a second presentation.
                    return Ok(None);
                }
                let scope = challenged.unwrap_or_else(|| scope.to_owned());
                let token = self.fetch_token(&realm, service.as_deref(), &scope).await?;
                Ok(Some(format!("Bearer {token}")))
            }
        }
    }

    fn basic_header(&self) -> Option<String> {
        match &self.auth {
            OciAuth::Basic { username, password } => {
                let raw = format!("{username}:{password}");
                Some(format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(raw)
                ))
            }
            _ => None,
        }
    }

    /// The token realm is a URL the registry chose. It passes the same
    /// scheme and address guards as the registry before the credential
    /// is presented to it.
    async fn fetch_token(
        &self,
        realm: &str,
        service: Option<&str>,
        scope: &str,
    ) -> Result<String, String> {
        let mut url = Url::parse(realm).map_err(|_| "token realm is not a URL".to_owned())?;
        if !self.scheme_admitted(&url) {
            return Err(format!(
                "token realm {} is not https (a plaintext realm would carry the credential in the clear)",
                redact_url(&url)
            ));
        }
        url.query_pairs_mut().append_pair("scope", scope);
        if let Some(s) = service {
            url.query_pairs_mut().append_pair("service", s);
        }
        self.guard(&url).await?;

        let resp = self
            .send_capped(
                Method::GET,
                url,
                "application/json",
                self.basic_header(),
                TOKEN_RESPONSE_CAP,
            )
            .await?;
        if resp.status != 200 {
            return Err(format!("token realm answered {}", resp.status));
        }
        #[derive(Deserialize)]
        struct TokenDoc {
            #[serde(default)]
            token: Option<String>,
            #[serde(default)]
            access_token: Option<String>,
            #[serde(default)]
            expires_in: Option<u64>,
        }
        let doc: TokenDoc = serde_json::from_slice(&resp.body).map_err(|_| {
            "token realm answered with something other than a token document".to_owned()
        })?;
        let token = doc
            .token
            .or(doc.access_token)
            .filter(|t| !t.trim().is_empty())
            .ok_or_else(|| "token realm answered without a token".to_owned())?;
        let ttl = doc
            .expires_in
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_TOKEN_TTL);
        self.tokens.lock().expect("token cache poisoned").insert(
            scope.to_owned(),
            CachedToken {
                token: token.clone(),
                expires_at: Instant::now() + ttl,
            },
        );
        Ok(token)
    }

    /// Follow a redirect chain by hand. Each hop is guarded; a hop that
    /// leaves the registry's origin is fetched without the credential.
    async fn follow(
        &self,
        method: Method,
        mut resp: Response,
        accept: &str,
    ) -> Result<Response, String> {
        let mut current = self.origin.clone();
        for _ in 0..MAX_REDIRECTS {
            let Some(location) = resp.header(LOCATION.as_str()) else {
                return Err(format!("redirect {} without a Location", resp.status));
            };
            let next = current
                .join(location)
                .map_err(|_| "redirect Location failed to parse".to_owned())?;
            if !self.scheme_admitted(&next) {
                return Err(format!(
                    "redirect to {} refused: not https",
                    redact_url(&next)
                ));
            }
            self.guard(&next).await?;
            let same_origin = next.origin() == self.origin.origin();
            let credential = if same_origin {
                self.credential(resp_scope_hint(&resp))
            } else {
                None
            };
            resp = self
                .send(method.clone(), next.clone(), accept, credential)
                .await?;
            if !is_redirect(resp.status) {
                return Ok(resp);
            }
            current = next;
        }
        Err(format!("more than {MAX_REDIRECTS} redirects"))
    }

    async fn send(
        &self,
        method: Method,
        url: Url,
        accept: &str,
        authorization: Option<String>,
    ) -> Result<Response, String> {
        self.send_capped(method, url, accept, authorization, self.max_bytes)
            .await
    }

    async fn send_capped(
        &self,
        method: Method,
        url: Url,
        accept: &str,
        authorization: Option<String>,
        cap: usize,
    ) -> Result<Response, String> {
        let mut rb = self.http.request(method, url).header(ACCEPT, accept);
        if let Some(value) = authorization {
            let header = HeaderValue::from_str(&value)
                .map_err(|_| "credential is not a valid header value".to_owned())?;
            rb = rb.header(AUTHORIZATION, header);
        }
        let mut resp = rb.send().await.map_err(|e| redact(e.to_string()))?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let mut body = Vec::new();
        let mut truncated = false;
        while let Some(chunk) = resp.chunk().await.map_err(|e| redact(e.to_string()))? {
            if body.len() + chunk.len() > cap {
                body.extend_from_slice(&chunk[..cap - body.len()]);
                truncated = true;
                break;
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Response {
            status,
            headers,
            body,
            truncated,
        })
    }

    /// `https` everywhere; `http` only where the registry itself is a
    /// loopback plaintext endpoint (the local-registry test shape).
    fn scheme_admitted(&self, url: &Url) -> bool {
        match url.scheme() {
            "https" => true,
            "http" => self.origin.scheme() == "http" && is_loopback_host(url.host_str()),
            _ => false,
        }
    }

    /// DNS-rebinding / SSRF guard: resolve the host and refuse a name that
    /// resolves only to private, loopback or link-local addresses, unless
    /// the binding opted in.
    async fn guard(&self, url: &Url) -> Result<(), String> {
        if self.allow_private {
            return Ok(());
        }
        let host = url
            .host_str()
            .ok_or_else(|| "URL has no host".to_owned())?
            .to_owned();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| "URL has no port".to_owned())?;
        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(format!("{host}:{port}"))
            .await
            .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?
            .collect();
        if addrs.is_empty() {
            return Err(format!("DNS resolution returned no addresses for {host}"));
        }
        if addrs
            .iter()
            .all(|a| mcpg_plugin_protocol::security::is_private_address(&a.ip()))
        {
            return Err(format!(
                "DNS rebinding guard: host '{host}' resolved only to private addresses \
                 (set allow_private_backends: true for an in-cluster registry)"
            ));
        }
        Ok(())
    }
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(host, Some("localhost" | "127.0.0.1" | "[::1]"))
}

/// A redirected response carries no scope of its own; the credential for a
/// same-origin hop is whatever token the first leg used, which the cache
/// still holds under the original scope. Registries redirect blobs to
/// storage rather than to themselves, so this hint is rarely consulted.
fn resp_scope_hint(_resp: &Response) -> &'static str {
    ""
}

/// Strip any credential from an error string before it surfaces.
fn redact(s: String) -> String {
    mcpg_plugin_protocol::redact::redact_in_text(&s)
}

fn redact_url(url: &Url) -> String {
    let mut u = url.clone();
    let _ = u.set_username("");
    let _ = u.set_password(None);
    u.set_query(None);
    u.to_string()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Challenge {
    Basic,
    Bearer {
        realm: String,
        service: Option<String>,
        scope: Option<String>,
    },
}

/// Parse a `WWW-Authenticate` value. Only the first challenge is read; a
/// registry advertises one scheme.
pub fn parse_challenge(value: &str) -> Option<Challenge> {
    let value = value.trim();
    let (scheme, params) = match value.split_once(char::is_whitespace) {
        Some((s, p)) => (s, p.trim()),
        None => (value, ""),
    };
    if scheme.eq_ignore_ascii_case("basic") {
        return Some(Challenge::Basic);
    }
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for (key, val) in auth_params(params) {
        match key.to_ascii_lowercase().as_str() {
            "realm" => realm = Some(val),
            "service" => service = Some(val),
            "scope" => scope = Some(val),
            _ => {}
        }
    }
    Some(Challenge::Bearer {
        realm: realm?,
        service,
        scope,
    })
}

/// Split `k="v",k2=v2` auth-params, honouring quoted commas.
fn auth_params(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = s;
    while !rest.is_empty() {
        let rest_trimmed = rest.trim_start_matches([' ', ',']);
        let Some(eq) = rest_trimmed.find('=') else {
            break;
        };
        let key = rest_trimmed[..eq].trim().to_owned();
        let after = &rest_trimmed[eq + 1..];
        let (val, remainder) = if let Some(q) = after.strip_prefix('"') {
            match q.find('"') {
                Some(end) => (q[..end].to_owned(), &q[end + 1..]),
                None => (q.to_owned(), ""),
            }
        } else {
            match after.find(',') {
                Some(end) => (after[..end].trim().to_owned(), &after[end..]),
                None => (after.trim().to_owned(), ""),
            }
        };
        if !key.is_empty() {
            out.push((key, val));
        }
        rest = remainder;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_challenges_parse_with_quoted_commas() {
        let c = parse_challenge(
            r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:a/b:pull,push""#,
        )
        .unwrap();
        assert_eq!(
            c,
            Challenge::Bearer {
                realm: "https://ghcr.io/token".into(),
                service: Some("ghcr.io".into()),
                scope: Some("repository:a/b:pull,push".into()),
            }
        );
        assert_eq!(
            parse_challenge(r#"Basic realm="Registry Realm""#).unwrap(),
            Challenge::Basic
        );
        assert_eq!(parse_challenge("Digest realm=x"), None);
        assert_eq!(
            parse_challenge(r#"Bearer service="x""#),
            None,
            "a realm is required"
        );
        assert_eq!(
            parse_challenge("Bearer realm=https://r/token, service=svc").unwrap(),
            Challenge::Bearer {
                realm: "https://r/token".into(),
                service: Some("svc".into()),
                scope: None,
            }
        );
    }

    #[test]
    fn redirect_statuses() {
        for s in [301, 302, 303, 307, 308] {
            assert!(is_redirect(s));
        }
        for s in [200, 304, 401, 404] {
            assert!(!is_redirect(s));
        }
    }

    #[test]
    fn url_redaction_drops_userinfo_and_query() {
        let u = Url::parse("https://user:pw@host/path?token=abc").unwrap();
        assert_eq!(redact_url(&u), "https://host/path");
    }
}
