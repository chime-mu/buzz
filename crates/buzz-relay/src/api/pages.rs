//! Buzz Pages: members-only static sites served from relay-hosted git repos.
//!
//! When `BUZZ_PAGES_HOST_PREFIX` is set (e.g. `apps.`), each site gets its own
//! origin, `<repo>--<owner16>.<prefix><community-host>`, where `<owner16>` is
//! the first 16 hex digits of the repo owner's pubkey. The community is the
//! one `<community-host>` resolves to, so the host-derived tenant boundary is
//! preserved.
//!
//! - `GET /<path>` on a site host serves `<path>` from the repo's `pages`
//!   branch, or its default branch when there is no `pages` branch.
//! - Every request re-checks what a git read checks: relay membership, bans,
//!   and active membership of the channel the repo is bound to.
//! - Browsers authenticate per site at `/_buzz/login` with a NIP-98 event
//!   signed for that URL (passed as `?token=`, or produced by a NIP-07
//!   extension on the login page). The relay answers with an HttpOnly,
//!   host-only session cookie, so site JavaScript never sees a credential.
//!
//! Sites are served on their own origins because they contain arbitrary
//! user-authored HTML and JavaScript: one site's scripts must not be able to
//! read another site, and the relay origin never serves either (see
//! `buzz-media`'s `serve_inline`).

use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use buzz_core::TenantContext;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::warn;

use crate::api::git::hydrate::{
    hydrate_for_read, load_manifest_for_read, HydratedRepo, HydrationOptions,
};
use crate::api::git::transport::{
    acquire_git_permit, authorize_git_read, deny_banned_git_principal, harden_git_env,
    validate_repo_id,
};
use crate::api::relay_members::{check_relay_membership, MembershipDecision};
use crate::state::AppState;

/// Branch served when present; otherwise the repo's default branch is used.
const PAGES_REF: &str = "refs/heads/pages";
/// Path of the login endpoint on every site host.
pub(crate) const LOGIN_PATH: &str = "/_buzz/login";
/// Caddy on-demand TLS "ask" endpoint: 200 only for hosts of existing sites.
const TLS_ASK_PATH: &str = "/_buzz/tls-ask";
/// Separator between repo id and owner prefix in a site label.
const LABEL_SEPARATOR: &str = "--";
/// Hex digits of the owner pubkey carried in a site label.
const OWNER_PREFIX_LEN: usize = 16;
/// How long a browser session lasts.
const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);
/// Disk held by hydrated repos kept warm for page requests.
const REPO_CACHE_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Idle time after which a hydrated repo is dropped from the cache.
const REPO_CACHE_IDLE: Duration = Duration::from_secs(10 * 60);
/// Longest request path accepted inside a site.
const MAX_SITE_PATH_LEN: usize = 1024;
/// Upper bound on one git subprocess.
const GIT_TIMEOUT: Duration = Duration::from_secs(15);
/// Repo announcements examined when resolving a site label to its owner.
const OWNER_LOOKUP_LIMIT: i64 = 50;

/// Buzz Pages configuration. Absent means the feature is disabled.
#[derive(Clone)]
pub struct PagesConfig {
    /// Host label prefix that selects the pages origins, e.g. `apps.`.
    pub host_prefix: String,
    /// HMAC key for session cookies.
    pub session_secret: Vec<u8>,
    /// Largest single file the relay will serve.
    pub max_file_bytes: u64,
}

impl std::fmt::Debug for PagesConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PagesConfig")
            .field("host_prefix", &self.host_prefix)
            .field("session_secret", &"[redacted]")
            .field("max_file_bytes", &self.max_file_bytes)
            .finish()
    }
}

/// Hydrated repos shared across page requests, weighed by bytes on disk.
/// Clones share one cache.
#[derive(Clone)]
pub struct PagesRepoCache(moka::future::Cache<String, Arc<HydratedRepo>>);

impl Default for PagesRepoCache {
    fn default() -> Self {
        Self(
            moka::future::Cache::builder()
                .max_capacity(REPO_CACHE_MAX_BYTES)
                .weigher(|_, repo: &Arc<HydratedRepo>| {
                    u32::try_from(repo.hydrated_bytes().max(1)).unwrap_or(u32::MAX)
                })
                .time_to_idle(REPO_CACHE_IDLE)
                .build(),
        )
    }
}

/// Why a page could not be produced. Only `NotFound` is the caller's fault;
/// everything else is a relay-side failure and must surface as 5xx.
#[derive(Debug, Clone)]
enum PageError {
    NotFound,
    Busy,
    Backend(String),
}

impl PageError {
    fn into_response(self) -> Response {
        match self {
            Self::NotFound => not_found(),
            Self::Busy => (StatusCode::SERVICE_UNAVAILABLE, "busy, retry shortly").into_response(),
            Self::Backend(reason) => {
                warn!(%reason, "pages: backend failure");
                (StatusCode::BAD_GATEWAY, "site temporarily unavailable").into_response()
            }
        }
    }
}

// ── Dispatch ────────────────────────────────────────────────────────────────

/// Which pages surface a request addresses.
#[derive(Debug, PartialEq, Eq)]
enum PagesHost {
    /// `<label>.<prefix><parent>`: one site.
    Site { label: String, parent: String },
    /// `<prefix><parent>`: no site lives here.
    Root,
}

/// Classify `host` against the pages prefix. `None` means the request is not
/// for Buzz Pages.
fn classify_host(prefix: &str, host: &str) -> Option<PagesHost> {
    let host = host.to_ascii_lowercase();
    if let Some(parent) = host.strip_prefix(prefix) {
        return (!parent.is_empty()).then_some(PagesHost::Root);
    }
    let (label, rest) = host.split_once('.')?;
    let parent = rest.strip_prefix(prefix)?;
    (!label.is_empty() && !parent.is_empty()).then(|| PagesHost::Site {
        label: label.to_string(),
        parent: parent.to_string(),
    })
}

/// Router middleware: answer pages-host requests, pass everything else on.
pub async fn pages_host_dispatch(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let Some(config) = state.config.pages.as_ref() else {
        return next.run(req).await;
    };
    let raw_host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    if req.uri().path() == TLS_ASK_PATH && raw_host.as_deref().is_some_and(is_internal_host) {
        return tls_ask(&state, config, req.uri().query()).await;
    }
    let Some(raw_host) = raw_host else {
        return next.run(req).await;
    };
    let Some(kind) = classify_host(&config.host_prefix, &raw_host) else {
        return next.run(req).await;
    };
    // A host that is itself a community is never shadowed by Pages.
    if crate::tenant::bind_community(&state.db, &raw_host)
        .await
        .is_ok()
    {
        return next.run(req).await;
    }
    match kind {
        PagesHost::Root => not_found(),
        PagesHost::Site { label, parent } => serve(&state, config, &label, &parent, req).await,
    }
}

async fn serve(
    state: &Arc<AppState>,
    config: &PagesConfig,
    label: &str,
    parent: &str,
    req: Request,
) -> Response {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if state.config.nip_fi.mode.restricts() {
        // NIP-FI admission is not wired into Pages; fail closed.
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Buzz Pages is unavailable while NIP-FI enforcement is on",
        )
            .into_response();
    }
    let tenant = match crate::tenant::bind_community(&state.db, parent).await {
        Ok(tenant) => tenant,
        Err(crate::tenant::BindError::UnmappedHost) => return not_found(),
        Err(crate::tenant::BindError::Lookup(_)) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "try again shortly").into_response()
        }
    };
    let Some((repo, owner_prefix)) = parse_label(label) else {
        return not_found();
    };
    let site_origin = format!(
        "{}://{label}.{}{}",
        public_scheme(&state.config.relay_url),
        config.host_prefix,
        tenant.host()
    );
    let secure = site_origin.starts_with("https://");
    let path = req.uri().path().to_string();

    if path == LOGIN_PATH {
        return login(
            state,
            config,
            &tenant,
            label,
            &site_origin,
            req.uri().query(),
        )
        .await;
    }
    let Some(session) = session_from_headers(config, &tenant, label, secure, req.headers()) else {
        return login_required(&path);
    };
    if let Err(denied) = relay_checks(state, &tenant, &session).await {
        return denied;
    }
    let owner = match resolve_owner(state, &tenant, repo, owner_prefix).await {
        Ok(owner) => owner,
        Err(e) => return e.into_response(),
    };
    if let Err(denied) = validate_repo_id(&owner, repo) {
        return denied;
    }
    if let Err(denied) =
        authorize_git_read(&state.db, tenant.community(), &session.pubkey, &owner, repo).await
    {
        return denied;
    }
    let Some(file) = site_file(&path) else {
        return not_found();
    };
    let head_only = req.method() == Method::HEAD;
    serve_file(state, config, &tenant, &owner, repo, &file, head_only)
        .await
        .unwrap_or_else(PageError::into_response)
}

/// The relay-level checks a git read performs, applied to a page session:
/// relay membership (NIP-43, honoring the agent attestation captured at
/// login) and community bans, cascaded to an agent's owner.
#[allow(clippy::result_large_err)] // Response is the natural error type for axum handlers
async fn relay_checks(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    session: &Session,
) -> Result<(), Response> {
    let auth_tag = session.auth_tag.as_deref();
    match check_relay_membership(
        state,
        tenant.community(),
        session.pubkey.as_bytes(),
        auth_tag,
        Some(session.login_at),
        None,
    )
    .await
    {
        Ok(MembershipDecision::Denied) => {
            return Err((StatusCode::FORBIDDEN, "restricted: not a relay member").into_response())
        }
        Ok(_) => {}
        Err(e) => {
            warn!(error = %e, "pages: relay membership lookup failed");
            return Err((StatusCode::SERVICE_UNAVAILABLE, "try again shortly").into_response());
        }
    }
    deny_banned_git_principal(
        &state.db,
        tenant.community(),
        &session.pubkey,
        auth_tag,
        Some(session.login_at),
        None,
    )
    .await
}

/// Whether `host` (a Host header) names a service on the internal network,
/// e.g. `relay:3000` as the TLS terminator calls it. Public names always
/// contain a dot, so tls-ask stays unreachable through the public proxy.
fn is_internal_host(host: &str) -> bool {
    let name = host.rsplit_once(':').map_or(host, |(name, _)| name);
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

// ── Site addressing ─────────────────────────────────────────────────────────

/// Split a site label into `(repo, owner_prefix)`. Repo ids must be DNS-safe:
/// lowercase letters, digits and `-`, not starting or ending with `-`. Labels
/// with `--` at positions 3–4 are reserved for IDNA (`xn--`), and CAs refuse
/// certificates for them, so 2-character repo ids cannot be sites.
fn parse_label(label: &str) -> Option<(&str, &str)> {
    if label.get(2..4) == Some(LABEL_SEPARATOR) {
        return None;
    }
    let (repo, owner_prefix) = label.rsplit_once(LABEL_SEPARATOR)?;
    let repo_ok = !repo.is_empty()
        && !repo.starts_with('-')
        && !repo.ends_with('-')
        && repo
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    let owner_ok = owner_prefix.len() == OWNER_PREFIX_LEN
        && owner_prefix
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
    (repo_ok && owner_ok).then_some((repo, owner_prefix))
}

/// Resolve the full owner pubkey for `repo` from the 16-hex-digit prefix in
/// the site label. Ambiguity (two announcing keys sharing the prefix) fails
/// closed as not found.
async fn resolve_owner(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    repo: &str,
    owner_prefix: &str,
) -> Result<String, PageError> {
    let query = buzz_db::EventQuery {
        kinds: Some(vec![30617]),
        d_tag: Some(repo.to_string()),
        global_only: true,
        limit: Some(OWNER_LOOKUP_LIMIT),
        ..buzz_db::EventQuery::for_community(tenant.community())
    };
    let events = state
        .db
        .query_events(&query)
        .await
        .map_err(|e| PageError::Backend(format!("repo lookup: {e}")))?;
    let mut owners = events
        .iter()
        .map(|e| e.event.pubkey.to_hex())
        .filter(|hex| hex.starts_with(owner_prefix));
    match (owners.next(), owners.next()) {
        (Some(owner), None) => Ok(owner),
        _ => Err(PageError::NotFound),
    }
}

/// Map a request path to a file inside the site. Directory paths get
/// `index.html`. Rejects `.`/`..` segments, malformed escapes and control
/// characters, so the result is safe to hand to git as `<oid>:<path>`.
fn site_file(path: &str) -> Option<String> {
    if path.len() > MAX_SITE_PATH_LEN {
        return None;
    }
    let decoded = percent_decode(path.strip_prefix('/')?)?;
    let mut file = String::new();
    for segment in decoded.split('/') {
        if segment == "." || segment == ".." {
            return None;
        }
        if segment.is_empty() {
            continue;
        }
        if !file.is_empty() {
            file.push('/');
        }
        file.push_str(segment);
    }
    if decoded.is_empty() || decoded.ends_with('/') {
        if !file.is_empty() {
            file.push('/');
        }
        file.push_str("index.html");
    }
    Some(file)
}

fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = input.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    let decoded = String::from_utf8(out).ok()?;
    (!decoded.chars().any(char::is_control)).then_some(decoded)
}

/// Percent-encode one path segment for a `Location` header.
fn encode_segment(segment: &str) -> String {
    segment
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

// ── Content ─────────────────────────────────────────────────────────────────

async fn serve_file(
    state: &Arc<AppState>,
    config: &PagesConfig,
    tenant: &TenantContext,
    owner: &str,
    repo: &str,
    file: &str,
    head_only: bool,
) -> Result<Response, PageError> {
    let manifest = load_manifest_for_read(&state.git_store, tenant, owner, repo)
        .await
        .map_err(|e| PageError::Backend(format!("manifest: {e}")))?
        .ok_or(PageError::NotFound)?;
    let served_ref = if manifest.refs.contains_key(PAGES_REF) {
        PAGES_REF
    } else {
        manifest.head.as_str()
    };
    let oid = manifest
        .refs
        .get(served_ref)
        .ok_or(PageError::NotFound)?
        .clone();

    // One permit covers hydration and every git call for this request, so
    // page traffic shares the relay's bound on concurrent git subprocesses.
    let _permit = acquire_git_permit(state, "pages").map_err(|_| PageError::Busy)?;
    let hydrated = hydrated_repo(state, tenant, owner, repo, &oid).await?;
    let object = format!("{oid}:{file}");

    let check = git_output(&hydrated, &["cat-file", "--batch-check"], Some(&object)).await?;
    let check = String::from_utf8_lossy(&check);
    let mut fields = check.split_whitespace();
    let (Some(_name), Some(kind), size) = (fields.next(), fields.next(), fields.next()) else {
        return Err(PageError::Backend(format!(
            "unexpected batch-check output: {check}"
        )));
    };
    match kind {
        "missing" | "ambiguous" => return Err(PageError::NotFound),
        "tree" => {
            let name = file.rsplit('/').next().unwrap_or(file);
            return Ok(redirect(&format!("{}/", encode_segment(name))));
        }
        "blob" => {}
        _ => return Err(PageError::NotFound),
    }
    let size: u64 = size
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| PageError::Backend(format!("unparseable size: {check}")))?;
    if size > config.max_file_bytes {
        return Ok(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    }
    let body = if head_only {
        Vec::new()
    } else {
        git_output(&hydrated, &["cat-file", "blob", &object], None).await?
    };

    let mut response = Response::new(Body::from(body));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type(file)),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    apply_site_headers(headers);
    Ok(response)
}

async fn hydrated_repo(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    owner: &str,
    repo: &str,
    oid: &str,
) -> Result<Arc<HydratedRepo>, PageError> {
    let key = format!("{}/{owner}/{repo}/{oid}", tenant.community());
    // `try_get_with` merges concurrent misses for one key into one hydration.
    state
        .pages_repo_cache
        .0
        .try_get_with(key, async {
            hydrate_for_read(
                &state.git_store,
                tenant,
                owner,
                repo,
                HydrationOptions {
                    pack_cache: &state.git_pack_cache,
                    scratch_dir: &state.config.git_repo_path,
                    max_pack_bytes: state.config.git_max_pack_bytes,
                    max_repo_bytes: state.config.git_max_repo_bytes,
                },
            )
            .await
            .map_err(|e| PageError::Backend(format!("hydrate: {e}")))?
            .map(Arc::new)
            .ok_or(PageError::NotFound)
        })
        .await
        .map_err(|e| (*e).clone())
}

/// Run a read-only git command in `repo`, optionally feeding one stdin line.
/// A non-zero exit or a timeout is a backend failure, never "not found":
/// callers establish existence with `--batch-check` first.
async fn git_output(
    repo: &HydratedRepo,
    args: &[&str],
    stdin_line: Option<&str>,
) -> Result<Vec<u8>, PageError> {
    let mut cmd = Command::new("git");
    harden_git_env(&mut cmd);
    cmd.current_dir(repo.path())
        .args(args)
        .kill_on_drop(true)
        .stdin(if stdin_line.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let run = async {
        let mut child = cmd
            .spawn()
            .map_err(|e| PageError::Backend(format!("spawn git: {e}")))?;
        if let (Some(line), Some(mut stdin)) = (stdin_line, child.stdin.take()) {
            stdin
                .write_all(format!("{line}\n").as_bytes())
                .await
                .map_err(|e| PageError::Backend(format!("git stdin: {e}")))?;
        }
        child
            .wait_with_output()
            .await
            .map_err(|e| PageError::Backend(format!("git wait: {e}")))
    };
    let output = tokio::time::timeout(GIT_TIMEOUT, run)
        .await
        .map_err(|_| PageError::Backend(format!("git {args:?} timed out")))??;
    if !output.status.success() {
        return Err(PageError::Backend(format!(
            "git {args:?} exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(output.stdout)
}

/// Headers on every served file. Each site already has its own origin; these
/// keep a site from being framed elsewhere or sniffed.
fn apply_site_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-cache"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'self'; form-action 'self'; base-uri 'self'"),
    );
}

fn content_type(file: &str) -> &'static str {
    let ext = file
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase());
    match ext.as_deref() {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json" | "map") => "application/json",
        Some("txt" | "md") => "text/plain; charset=utf-8",
        Some("csv") => "text/csv; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("wasm") => "application/wasm",
        Some("pdf") => "application/pdf",
        _ => "application/octet-stream",
    }
}

// ── TLS ask ─────────────────────────────────────────────────────────────────

/// Caddy on-demand TLS asks before issuing a certificate for `?domain=`.
/// Answer 200 only for the host of an existing site, so arbitrary labels
/// under the wildcard cannot burn certificate-issuance rate limits.
async fn tls_ask(state: &Arc<AppState>, config: &PagesConfig, query: Option<&str>) -> Response {
    let domain = query
        .map(|q| url::form_urlencoded::parse(q.as_bytes()).into_owned())
        .and_then(|mut pairs| pairs.find(|(k, _)| k == "domain").map(|(_, v)| v));
    let Some(PagesHost::Site { label, parent }) = domain
        .as_deref()
        .and_then(|d| classify_host(&config.host_prefix, d))
    else {
        return not_found();
    };
    let Some((repo, owner_prefix)) = parse_label(&label) else {
        return not_found();
    };
    let Ok(tenant) = crate::tenant::bind_community(&state.db, &parent).await else {
        return not_found();
    };
    match resolve_owner(state, &tenant, repo, owner_prefix).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(_) => not_found(),
    }
}

// ── Sessions ────────────────────────────────────────────────────────────────

/// A verified page session.
struct Session {
    pubkey: nostr::PublicKey,
    /// When the login token was signed; anchors the NIP-OA attestation check.
    login_at: u64,
    /// The agent's NIP-OA attestation from the login event, if any.
    auth_tag: Option<String>,
}

fn cookie_name(secure: bool) -> &'static str {
    // `__Host-` binds the cookie to this exact origin (Secure, Path=/, no
    // Domain), so no other host can set or shadow it.
    if secure {
        "__Host-buzz_pages"
    } else {
        "buzz_pages"
    }
}

async fn login(
    state: &Arc<AppState>,
    config: &PagesConfig,
    tenant: &TenantContext,
    label: &str,
    site_origin: &str,
    query: Option<&str>,
) -> Response {
    let params: Vec<(String, String)> = query
        .map(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_default();
    let param = |name: &str| {
        params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    let next = param("next").filter(|n| is_local_path(n)).unwrap_or("/");

    let Some(token) = param("token") else {
        return login_page(next);
    };
    let Some(event_json) = URL_SAFE_NO_PAD
        .decode(token.trim_end_matches('='))
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
    else {
        return (StatusCode::BAD_REQUEST, "malformed login token").into_response();
    };
    let login_url = format!("{site_origin}{LOGIN_PATH}");
    let pubkey = match buzz_auth::nip98::verify_nip98_event(&event_json, &login_url, "GET", None) {
        Ok(pubkey) => pubkey,
        Err(e) => {
            warn!(error = %e, "pages: login token rejected");
            return (
                StatusCode::UNAUTHORIZED,
                "login link expired or invalid — ask for a new one",
            )
                .into_response();
        }
    };
    let Ok(event) = serde_json::from_str::<nostr::Event>(&event_json) else {
        return (StatusCode::BAD_REQUEST, "malformed login token").into_response();
    };
    let session = Session {
        pubkey,
        login_at: event.created_at.as_secs(),
        auth_tag: crate::handlers::auth::extract_auth_tag_json(&event),
    };
    if let Err(denied) = relay_checks(state, tenant, &session).await {
        return denied;
    }

    let expires = unix_now() + SESSION_TTL.as_secs();
    let Some(cookie_value) = sign_session(config, tenant, label, &session, expires) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let secure = site_origin.starts_with("https://");
    let cookie = format!(
        "{}={cookie_value}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax{}",
        cookie_name(secure),
        SESSION_TTL.as_secs(),
        if secure { "; Secure" } else { "" }
    );
    let mut response = redirect(next);
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

/// Only same-origin absolute paths made of visible ASCII are valid
/// post-login destinations. Browsers strip tabs and newlines from URLs, so
/// `/\t/evil` would otherwise become the protocol-relative `//evil`.
fn is_local_path(next: &str) -> bool {
    next.starts_with('/')
        && !next.starts_with("//")
        && next.bytes().all(|b| b.is_ascii_graphic() && b != b'\\')
}

fn session_mac(config: &PagesConfig, payload: &str) -> Option<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&config.session_secret).ok()?;
    mac.update(payload.as_bytes());
    Some(hex::encode(mac.finalize().into_bytes()))
}

/// Cookie: `v2.<pubkey>.<community>.<label>.<expires>.<login_at>.<tag>.<mac>`
/// where `<tag>` is the base64url NIP-OA tag JSON or `-`.
fn sign_session(
    config: &PagesConfig,
    tenant: &TenantContext,
    label: &str,
    session: &Session,
    expires: u64,
) -> Option<String> {
    let tag = session
        .auth_tag
        .as_deref()
        .map(|t| URL_SAFE_NO_PAD.encode(t))
        .unwrap_or_else(|| "-".to_string());
    let payload = format!(
        "v2.{}.{}.{label}.{expires}.{}.{tag}",
        session.pubkey.to_hex(),
        tenant.community(),
        session.login_at
    );
    let mac = session_mac(config, &payload)?;
    Some(format!("{payload}.{mac}"))
}

/// The first valid, unexpired session cookie for this site, if any. Every
/// cookie with the session name is tried, so a stray same-named cookie
/// cannot lock a user out.
fn session_from_headers(
    config: &PagesConfig,
    tenant: &TenantContext,
    label: &str,
    secure: bool,
    headers: &HeaderMap,
) -> Option<Session> {
    let name = cookie_name(secure);
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(n, _)| *n == name)
        .find_map(|(_, value)| verify_session(config, tenant, label, value))
}

fn verify_session(
    config: &PagesConfig,
    tenant: &TenantContext,
    label: &str,
    value: &str,
) -> Option<Session> {
    let (payload, mac) = value.rsplit_once('.')?;
    let expected = session_mac(config, payload)?;
    let mac_ok: bool = subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), mac.as_bytes()).into();
    if !mac_ok {
        return None;
    }
    let fields: Vec<&str> = payload.split('.').collect();
    let ["v2", pubkey, community, site, expires, login_at, tag] = fields.as_slice() else {
        return None;
    };
    if *community != tenant.community().to_string()
        || *site != label
        || expires.parse::<u64>().ok()? <= unix_now()
    {
        return None;
    }
    let auth_tag = match *tag {
        "-" => None,
        encoded => Some(String::from_utf8(URL_SAFE_NO_PAD.decode(encoded).ok()?).ok()?),
    };
    Some(Session {
        pubkey: nostr::PublicKey::from_hex(pubkey).ok()?,
        login_at: login_at.parse().ok()?,
        auth_tag,
    })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `wss://` / `https://` relays put pages on https; anything else is local dev.
fn public_scheme(relay_url: &str) -> &'static str {
    if relay_url.starts_with("wss://") || relay_url.starts_with("https://") {
        "https"
    } else {
        "http"
    }
}

// ── Responses ───────────────────────────────────────────────────────────────

fn redirect(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

fn html_response(status: StatusCode, body: String) -> Response {
    let mut response = (status, body.replace("{style}", PAGE_STYLE)).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        ),
    );
    response
}

fn login_required(path: &str) -> Response {
    let next = url::form_urlencoded::byte_serialize(path.as_bytes()).collect::<String>();
    html_response(
        StatusCode::UNAUTHORIZED,
        LOGIN_REQUIRED_HTML.replace("{login}", &format!("{LOGIN_PATH}?next={next}")),
    )
}

fn login_page(next: &str) -> Response {
    let next_json = serde_json::to_string(next).unwrap_or_else(|_| "\"/\"".to_string());
    html_response(
        StatusCode::OK,
        LOGIN_PAGE_HTML.replace("{next_json}", &next_json.replace('<', "\\u003c")),
    )
}

const PAGE_STYLE: &str = "body{font-family:-apple-system,system-ui,sans-serif;background:#14120f;color:#efe9df;display:grid;place-items:center;min-height:100vh;margin:0}main{max-width:420px;padding:32px;background:#1f1c17;border:1px solid #39342b;border-radius:16px}h1{font-size:20px;margin:0 0 8px}p{color:#cfc6b8;line-height:1.5;font-size:14px}a,button{display:inline-block;margin-top:8px;padding:10px 16px;border-radius:10px;background:#f5b52e;color:#14120f;font-weight:600;border:0;text-decoration:none;font-size:14px;cursor:pointer}code{color:#f5c955}#err{color:#f39a6b}";

const LOGIN_REQUIRED_HTML: &str = concat!(
    "<!doctype html><html><head><meta charset=utf-8><title>Buzz Pages</title><style>",
    "{style}",
    "</style></head><body><main><h1>Members only</h1>",
    "<p>This app is shared inside a Buzz community. Sign in to view it.</p>",
    "<a href=\"{login}\">Sign in</a>",
    "<p>Or run <code>buzz pages link</code> to get a short-lived login link.</p>",
    "</main></body></html>"
);

const LOGIN_PAGE_HTML: &str = concat!(
    "<!doctype html><html><head><meta charset=utf-8><title>Buzz Pages · Sign in</title><style>",
    "{style}",
    "</style></head><body><main><h1>Sign in to Buzz Pages</h1>",
    "<p>Sign with your Nostr key using a browser extension (NIP-07), or open a login link from <code>buzz pages link</code>.</p>",
    "<button id=go>Sign in with extension</button><p id=err></p>",
    "<script>const next={next_json};",
    "document.getElementById('go').onclick=async()=>{const err=document.getElementById('err');",
    "if(!window.nostr){err.textContent='No Nostr extension found.';return}",
    "try{const u=location.origin+location.pathname;",
    "const ev=await window.nostr.signEvent({kind:27235,created_at:Math.floor(Date.now()/1000),tags:[['u',u],['method','GET']],content:''});",
    "const t=btoa(unescape(encodeURIComponent(JSON.stringify(ev)))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');",
    "location.href=u+'?token='+t+'&next='+encodeURIComponent(next)}catch(e){err.textContent=String(e)}};",
    "</script></main></body></html>"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_classification() {
        let site = |label: &str, parent: &str| {
            Some(PagesHost::Site {
                label: label.into(),
                parent: parent.into(),
            })
        };
        let cases: &[(&str, Option<PagesHost>)] = &[
            (
                "Team-Dash--0123456789abcdef.Apps.Buzz.Example",
                site("team-dash--0123456789abcdef", "buzz.example"),
            ),
            ("apps.buzz.example", Some(PagesHost::Root)),
            ("buzz.example", None),
            ("x.buzz.example", None),
            ("apps.", None),
            (".apps.buzz.example", None),
        ];
        for (host, expected) in cases {
            assert_eq!(&classify_host("apps.", host), expected, "{host}");
        }
    }

    #[test]
    fn label_parsing() {
        assert_eq!(
            parse_label("team-dash--0123456789abcdef"),
            Some(("team-dash", "0123456789abcdef"))
        );
        assert_eq!(
            parse_label("a--b--0123456789abcdef"),
            Some(("a--b", "0123456789abcdef"))
        );
        for bad in [
            "team-dash",
            "team-dash--0123",
            "--0123456789abcdef",
            "-x--0123456789abcdef",
            "x---0123456789abcdef",
            "Team--0123456789abcdef",
            "x--0123456789ABCDEF",
            "x--0123456789abcdeg",
            "ui--0123456789abcdef",
            "ab--x--0123456789abcdef",
        ] {
            assert_eq!(parse_label(bad), None, "{bad} must be rejected");
        }
    }

    #[test]
    fn tls_ask_is_internal_only() {
        for host in ["relay:3000", "relay", "buzz-relay_1:3000", "localhost:3000"] {
            assert!(is_internal_host(host), "{host} is internal");
        }
        for host in [
            "",
            ":3000",
            "buzz.mu.dk",
            "buzz.mu.dk:1",
            "buzz.mu.dk:",
            "x--0123456789abcdef.apps.buzz.mu.dk",
            "127.0.0.1:3000",
            "[::1]:3000",
        ] {
            assert!(!is_internal_host(host), "{host} is public");
        }
    }

    #[test]
    fn site_file_mapping() {
        assert_eq!(site_file("/").as_deref(), Some("index.html"));
        assert_eq!(site_file("/docs/").as_deref(), Some("docs/index.html"));
        assert_eq!(
            site_file("/assets/app%20v2.js").as_deref(),
            Some("assets/app v2.js")
        );
        for bad in ["/../secret", "/a/%2e%2e/b", "/a%00b", "/%zz", "/a%09b", ""] {
            assert_eq!(site_file(bad), None, "{bad:?} must be rejected");
        }
    }

    #[test]
    fn post_login_redirect_stays_on_origin() {
        assert!(is_local_path("/docs/?tab=1"));
        for bad in [
            "//evil.example",
            "https://evil.example",
            "/\\evil.example",
            "/\t/evil.example",
            "/\n/evil.example",
            "/ /evil.example",
            "",
        ] {
            assert!(!is_local_path(bad), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn redirect_segment_is_encoded() {
        assert_eq!(encode_segment("a b?#é"), "a%20b%3F%23%C3%A9");
    }

    #[test]
    fn session_round_trip_and_binding() {
        let config = PagesConfig {
            host_prefix: "apps.".into(),
            session_secret: vec![7; 32],
            max_file_bytes: 1,
        };
        let community = || buzz_core::CommunityId::from_uuid(uuid::Uuid::new_v4());
        let tenant = TenantContext::resolved(community(), "buzz.example");
        let other = TenantContext::resolved(community(), "buzz.example");
        let keys = nostr::Keys::generate();
        let session = Session {
            pubkey: keys.public_key(),
            login_at: 1,
            auth_tag: Some("[\"auth\",\"x\"]".into()),
        };
        let label = "s--0123456789abcdef";
        let cookie = sign_session(&config, &tenant, label, &session, u64::MAX).expect("signs");

        let ok = verify_session(&config, &tenant, label, &cookie).expect("valid");
        assert_eq!(ok.pubkey, keys.public_key());
        assert_eq!(ok.auth_tag.as_deref(), Some("[\"auth\",\"x\"]"));

        assert!(verify_session(&config, &tenant, "t--0123456789abcdef", &cookie).is_none());
        assert!(verify_session(&config, &other, label, &cookie).is_none());
        let mut tampered = cookie.clone();
        let last = tampered.pop();
        tampered.push(if last == Some('0') { '1' } else { '0' });
        assert!(verify_session(&config, &tenant, label, &tampered).is_none());
        let expired = sign_session(&config, &tenant, label, &session, 1).expect("signs");
        assert!(verify_session(&config, &tenant, label, &expired).is_none());
    }
}
