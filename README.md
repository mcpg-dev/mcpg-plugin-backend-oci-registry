# `dev.mcpg.backend.oci-registry` — OCI container-registry backend

Read-only access to any registry speaking the [OCI distribution
API](https://github.com/opencontainers/distribution-spec) — GHCR, Docker Hub,
Harbor, Quay, ECR, GCR / Artifact Registry, `distribution/registry` — as MCP
tools, resources and change notifications. One binding is one operation
against one registry; the registry origin, the repositories the binding may
reach, the credential and the transport limits are operator-fixed, and the
model supplies only a repository (when the binding admits a choice), a
reference and paging.

Nothing pushes, deletes or downloads a layer.

## Operations

| `operation` | Request | Result (`response`) |
|---|---|---|
| `catalog` | `GET /v2/_catalog` | `repositories[]` filtered to the binding's allowlist, `next_last` paging cursor |
| `tags` | `GET /v2/<repo>/tags/list` | `repository`, `tags[]`, `next_last` |
| `resolve` | `HEAD /v2/<repo>/manifests/<ref>` (GET fallback) | `digest`, `media_type`, `size` |
| `manifest` | `GET /v2/<repo>/manifests/<ref>` | `digest`, `media_type`, `size`, `is_index`, `platforms[]` (index) or `config_digest` + `layers[]` (image), `annotations`, the raw `manifest` |
| `image_config` | manifest → platform manifest → `GET /v2/<repo>/blobs/<config>` | `digest`, `index_digest`, `config_digest`, `platform`, `created`, `labels`, `env`, `entrypoint`, `cmd`, `working_dir`, `user`, `exposed_ports`, `volumes`, `layers[]`, `total_size`, `annotations`, the raw `config` |
| `referrers` | `GET /v2/<repo>/referrers/<digest>` with fallbacks | `subject`, `referrers[]` (`digest`, `media_type`, `artifact_type`, `size`, `annotations`; cosign entries add `tag` + `layers`), `source` |

`referrers` resolves a tag to its digest first. Registries without the OCI 1.1
referrers API fall back to the `<algorithm>-<hex>` tag schema and then to
cosign's own `<algorithm>-<hex>.sig` / `.att` / `.sbom` tags, which is what
most public registries actually hold; those entries report
`artifact_type: application/vnd.dev.cosign.{signature,attestation,sbom}`.

Every manifest and blob is **digest-verified**: the bytes are hashed and
compared with the digest requested (when the reference is one) and with the
digest the registry declared. Bytes that do not match are an error, never
metadata.

### Tool arguments

| Argument | Operations | Description |
|---|---|---|
| `repository` | all but `catalog` | Required unless the binding sets `default_repository`; must be admitted by the binding. |
| `reference` | `resolve`, `manifest`, `image_config`, `referrers` | A tag or `sha256:…` digest. Defaults to `default_reference`, else `latest`. |
| `n`, `last` | `catalog`, `tags` | Page size (1..=1000) and the previous page's `next_last`. |
| `platform` | `image_config` | `os/arch[/variant]` to select from a multi-platform index (default `default_platform`, `linux/amd64`). |
| `artifact_type` | `referrers` | Only referrers of this artifact type. |

## Binding config (`backend: { kind: oci_registry, ... }`)

| Field | Type | Default | Description |
|---|---|---|---|
| `registry` | string | *(required)* | Registry origin, `https://` (or `http://localhost` for a local registry). No userinfo, query or fragment. |
| `operation` | enum | *(required)* | One of the operations above. |
| `repository_allowlist` | array | `[]` | Exact names (`org/app`) or prefixes ending in `/*` (`org/*` admits `org/app` and `org/team/app`, not `org`). |
| `default_repository` | string | — | Used when the call names none; always admitted. |
| `allow_any_repository` | bool | `false` | Admit every repository the registry serves (logged at register). |
| `default_reference` | string | — | Used when the call names none (`latest` otherwise). |
| `default_platform` | string | `linux/amd64` | Platform picked from an index when the call names none. |
| `auth` | object | `{kind: none}` | `none`, `basic {username, password}` or `bearer {token}` — see below. |
| `tls.ca_cert_pem` | string | — | Inline PEM CA for a private registry. |
| `tls.insecure_skip_verify` | bool | `false` | Loopback registries only; register fails otherwise. |
| `allow_private_backends` | bool | `false` | Allow private/loopback resolved addresses (in-cluster registries). |
| `connect_timeout_ms` / `operation_timeout_ms` | int | `5000` / `30000` | Per-request budgets. |
| `max_response_bytes` | int | `4194304` | Cap on any single body read; manifests and configs are small documents. |
| `page_size` | int | `100` | Default page size for `catalog`, `tags` and `resources/list`. |
| `surface` | enum | `tool` | `tool` or `resource` (see below). |
| `uri` | string | — | Static resource URI for the resource surface. |

A repository-addressing operation needs one of `default_repository`,
`repository_allowlist` or `allow_any_repository`, or register fails.

### Authentication

`kind: none` is not "no auth": the plugin completes the registry's
**anonymous token challenge** (the distribution token flow), which is how
public repositories on Docker Hub and GHCR are read. `kind: basic` presents
the pair to the token realm on a `Bearer` challenge and directly on a `Basic`
one — never proactively, so the password reaches only an endpoint that asked.
`kind: bearer` sends a static token as-is. Tokens obtained from a realm are
cached per scope until shortly before they expire.

The secret-bearing fields take `${env.X}` (resolved at config load) or
`cred://<plugin>/<target>` (resolved per caller at dispatch). The resolved
secret never reaches logs or the response envelope.

## Example

```yaml
# 1. Load the backend plugin artifact (top-level `plugins:` is a flat list).
plugins:
  - id: dev.mcpg.backend.oci-registry
    class: backend
    source: { oci: "oci://ghcr.io/mcpg-dev/plugins/backend-oci-registry:protocol-1" }

# 2. Declare each binding as a tool under `mcp.capabilities.tools[]`.
mcp:
  capabilities:
    tools:
      - name: images.tags
        description: List the tags of one of our container images.
        backend:
          kind: oci_registry
          registry: https://ghcr.io
          operation: tags
          repository_allowlist: ["acme/*"]
      - name: images.inspect
        description: Labels, entrypoint, layers and size of an image reference.
        backend:
          kind: oci_registry
          registry: https://ghcr.io
          operation: image_config
          repository_allowlist: ["acme/*"]
          default_platform: linux/arm64
          auth:
            kind: basic
            username: ci-bot
            password: "${env.GHCR_TOKEN}"
      - name: images.signatures
        description: Signatures, SBOMs and attestations attached to an image.
        backend:
          kind: oci_registry
          registry: https://ghcr.io
          operation: referrers
          default_repository: acme/app
```

## MCP surfaces & composition

### As a resource

Place a binding under `mcp.capabilities.resources[]` (or
`resource_templates[]`) with `surface: resource`. A successful result is
reshaped into the `resources/read` `{contents:[…]}` body; a failed one keeps
the envelope with `downstreamError`. The requested URI names the repository
and reference — `oci://<registry host>/<repository>:<tag>` or
`@<digest>` — and a URI on another registry is refused.

`resources/list` enumerates the tags of `default_repository` as
`oci://<host>/<repository>:<tag>` entries (a `catalog` binding lists
repositories instead), paging through the registry's own `last` cursor.
Template variables `repository` (from the catalog, allowlist-filtered) and
`reference` (tags of the repository in the completion context, or the
default) complete.

```yaml
  capabilities:
    resource_templates:
      - name: image
        description: The image config behind any admitted reference.
        uri_template: "oci://ghcr.io/{repository}:{reference}"
        backend:
          kind: oci_registry
          registry: https://ghcr.io
          operation: image_config
          repository_allowlist: ["acme/*"]
          surface: resource
```

### As a pipeline step

The kind is `pipeline_capable`: an `oci_registry` step in a backend pipeline
runs the operation with the step's arguments and passes the envelope on.

### Schemas & annotations

`input_schema` is derived per operation (`repository` is required only when
the binding has no default); `output_schema` describes the envelope. Every
operation is read-only, so `annotations: { read_only: true }` is accurate on
any binding.

## Change-watching

A resource can subscribe to a registry through the plugin's second entity —
a **polling `watch_strategy`** (kind `oci_registry_poll`). Registries have no
change-push channel, but two cheap reads tell whether an image moved: with a
`reference`, the cursor is the digest the tag resolves to (a `HEAD` per
tick), so a re-pushed `latest` fires; without one, the cursor is a
fingerprint of the repository's full sorted tag set, so a new version tag
fires. The first tick only records a baseline.

```yaml
mcp:
  capabilities:
    resources:
      - name: images.app_latest
        description: The digest our app image currently ships as.
        uri: "oci://ghcr.io/acme/app:latest"
        backend:
          kind: oci_registry
          registry: https://ghcr.io
          operation: image_config
          default_repository: acme/app
          default_reference: latest
          surface: resource
        watch:
          strategy:
            type: plugin
            kind: oci_registry_poll
            registry: https://ghcr.io
            repository: acme/app
            reference: latest          # omit to watch the tag set instead
            auth: { kind: basic, username: ci-bot, password: "${cred://ghcr/token}" }
            interval_ms: 30000
```

| Field | Type | Default | Description |
|---|---|---|---|
| `registry` | string | *(required)* | Same shape as the binding. |
| `auth` / `tls` | object | — | Same shape as the binding. |
| `repository` | string | *(required)* | Repository to watch. |
| `reference` | string | — | Tag whose digest is the cursor; absent = watch the tag set. |
| `allow_private_backends` | bool | `false` | Allow private/loopback resolved addresses. |
| `interval_ms` | int | `60000` | Poll cadence (floored at 250 ms). |
| `timeout_ms` | int | `10000` | Per-tick request budget. |

A tag-set watch walks at most 50 pages of 1000 tags per tick. A 404 (a tag
that does not exist yet, an empty repository) is "no signal", not a change;
transient failures are logged and retried on the next tick.

## Security

- **Origin constraint**: `https://` required; `http://` admitted for loopback
  only. Userinfo in the origin is refused — credentials go in `auth`.
- **DNS-rebinding / SSRF guard** on the registry host, and on the two URLs a
  registry hands the client — the token realm in a `WWW-Authenticate`
  challenge and the `Location` of a storage redirect. A host resolving only
  to private/loopback/link-local addresses is refused unless
  `allow_private_backends` is set. A plaintext realm or redirect target off
  loopback is refused before it is dialled.
- **Credential containment**: a redirect that leaves the registry's origin is
  fetched without the credential (storage never sees the registry token);
  Basic is presented only in answer to a challenge; the token realm gets the
  Basic pair only over the guarded, https-only URL.
- **Bounded bodies**: every read stops at `max_response_bytes`; token
  documents at 64 KiB; at most 5 redirect hops. Layers are never fetched.
- **Name grammar**: repositories, tags and digests are validated against the
  distribution grammar before they are spliced into a path, and paging
  cursors are validated as names. A value that fails the grammar is refused,
  not escaped.
- **Read-only**: no operation writes to a registry.
- **Redacting Debug** on `auth` and `tls`; transport errors pass through the
  shared credential redactor.

## Observability

Per call the plugin emits `mcpg_oci_registry_backend_latency_seconds` and
`mcpg_oci_registry_backend_calls_total` with a closed `outcome` label set
(`ok`, `registry_4xx`, `registry_5xx`, `timeout`, `transport`,
`digest_mismatch`), and audit events on driver-class failures
(`dev.mcpg.backend.oci-registry.request_timeout` / `.request_failed` /
`.upstream_5xx`) and on a digest mismatch (`.digest_mismatch`). Audit metadata
carries `oci.operation`, `oci.registry` and `oci.repository_mode`.

## Testing

- `cargo test -p mcpg-plugin-backend-oci-registry` — unit tests (grammar,
  allowlist, challenge parsing, schemas, envelope shaping) plus the offline
  `wiremock` contract suite: token challenge and per-scope cache, Link
  pagination and allowlist filtering, digest verification, platform
  selection, the storage redirect with the credential stripped off-origin, a
  refused plaintext redirect, the referrers fallbacks, the 4xx envelope, the
  resource surface, and the poll watcher.
- `cargo test -p mcpg-plugin-backend-oci-registry --test wiremock_smoke live_ghcr -- --ignored`
  — against the real GHCR (network): anonymous token challenge, tags,
  index → platform → digest-verified manifest → config blob through GHCR's
  storage redirect, cosign signature discovery.
