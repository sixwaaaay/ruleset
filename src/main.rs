use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, Query, Request},
    http::{HeaderValue, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use ipnet::IpNet;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::{fs, net::TcpListener};
use tower_http::compression::CompressionLayer;
use tracing_subscriber::EnvFilter;

// Env var names and defaults
const ENV_BIND_ADDR: &str = "BIND_ADDR";
const ENV_ADMIN_TOKEN: &str = "ADMIN_TOKEN";
const ENV_DATA_FILE: &str = "DATA_FILE";
const ENV_FE_DIR: &str = "FE_DIR";
const DEFAULT_BIND_ADDR: &str = "0.0.0.0:3500";
const DEFAULT_DATA_FILE: &str = "rulesets.json";
const DEFAULT_FE_DIR: &str = "frontend/dist";

// Data file path and frontend static dir (overridable via env)
static DATA_FILE: LazyLock<String> =
    LazyLock::new(|| env::var(ENV_DATA_FILE).unwrap_or_else(|_| DEFAULT_DATA_FILE.to_string()));
static FE_DIR: LazyLock<String> =
    LazyLock::new(|| env::var(ENV_FE_DIR).unwrap_or_else(|_| DEFAULT_FE_DIR.to_string()));

// Admin token: taken from ADMIN_TOKEN env, or auto-generated and logged when missing
static ADMIN_TOKEN: LazyLock<String> = LazyLock::new(|| {
    if let Ok(value) = env::var(ENV_ADMIN_TOKEN) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("system RNG unavailable");
    let token: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    tracing::warn!(
        "{ENV_ADMIN_TOKEN} is not set; generated a random admin token (lost on restart): {token}"
    );
    token
});

// Global state: slug -> ruleset
static RULESETS: LazyLock<Mutex<HashMap<String, Ruleset>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

// Frontend entry page is read into memory once at startup; a placeholder is shown when missing
static INDEX_HTML: LazyLock<String> = LazyLock::new(|| {
    let path = format!("{}/index.html", FE_DIR.as_str());
    std::fs::read_to_string(&path).unwrap_or_else(|_| {
        format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Rule Sets Manager</title></head>\
             <body><p>Frontend not built yet. Run <code>npm --prefix frontend install &amp;&amp; npm --prefix frontend build</code>\
             or point the {ENV_FE_DIR} env var at a directory with a built UI.</p></body></html>"
        )
    })
});

// Custom error type; the mapping to HTTP statuses lives here
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Invalid IP CIDR format: {0}")]
    InvalidIpCidr(String),
    #[error("Invalid domain format: {0}")]
    InvalidDomain(String),
    #[error("Invalid port number: {0}")]
    InvalidPort(String),
    #[error("Rule already exists")]
    DuplicateRule,
    #[error("Rule not found")]
    RuleNotFound,
    #[error("Ruleset not found")]
    RulesetNotFound,
    #[error("Ruleset name already exists")]
    DuplicateName,
    #[error("Invalid ruleset name")]
    InvalidName,
    #[error("Invalid slug")]
    InvalidSlug,
    #[error("Not found")]
    NotFound,
    #[error("Unauthorized")]
    Unauthorized,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, www_auth) = match self {
            ApiError::InvalidIpCidr(_)
            | ApiError::InvalidDomain(_)
            | ApiError::InvalidPort(_)
            | ApiError::InvalidName
            | ApiError::InvalidSlug => (StatusCode::BAD_REQUEST, false),
            ApiError::DuplicateRule | ApiError::DuplicateName => (StatusCode::CONFLICT, false),
            ApiError::RuleNotFound | ApiError::RulesetNotFound | ApiError::NotFound => {
                (StatusCode::NOT_FOUND, false)
            }
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, true),
            ApiError::IoError(_) | ApiError::JsonError(_) => {
                // Keep internal error details out of client responses
                tracing::error!("internal error: {self}");
                (StatusCode::INTERNAL_SERVER_ERROR, false)
            }
        };
        let body = Json(serde_json::json!({ "error": self.to_string() }));
        let mut response = (status, body).into_response();
        if www_auth {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
        }
        response
    }
}

// One rule type
#[derive(Debug, Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
enum RuleType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainWildcard,
    DomainRegex,
    Geosite,
    IpCidr,
    IpCidr6,
    IpSuffix,
    IpAsn,
    Geoip,
    SrcGeoip,
    SrcIpAsn,
    SrcIpCidr,
    SrcIpSuffix,
    DstPort,
    SrcPort,
    InPort,
    InType,
    InUser,
    InName,
    ProcessPath,
    ProcessPathRegex,
    ProcessName,
    ProcessNameRegex,
    Uid,
    Network,
    Dscp,
    Match,
}

impl std::fmt::Display for RuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use RuleType::*;
        let s = match self {
            Domain => "DOMAIN",
            DomainSuffix => "DOMAIN-SUFFIX",
            DomainKeyword => "DOMAIN-KEYWORD",
            DomainWildcard => "DOMAIN-WILDCARD",
            DomainRegex => "DOMAIN-REGEX",
            Geosite => "GEOSITE",
            IpCidr => "IP-CIDR",
            IpCidr6 => "IP-CIDR6",
            IpSuffix => "IP-SUFFIX",
            IpAsn => "IP-ASN",
            Geoip => "GEOIP",
            SrcGeoip => "SRC-GEOIP",
            SrcIpAsn => "SRC-IP-ASN",
            SrcIpCidr => "SRC-IP-CIDR",
            SrcIpSuffix => "SRC-IP-SUFFIX",
            DstPort => "DST-PORT",
            SrcPort => "SRC-PORT",
            InPort => "IN-PORT",
            InType => "IN-TYPE",
            InUser => "IN-USER",
            InName => "IN-NAME",
            ProcessPath => "PROCESS-PATH",
            ProcessPathRegex => "PROCESS-PATH-REGEX",
            ProcessName => "PROCESS-NAME",
            ProcessNameRegex => "PROCESS-NAME-REGEX",
            Uid => "UID",
            Network => "NETWORK",
            Dscp => "DSCP",
            Match => "MATCH",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
struct Rule {
    rule_type: RuleType,
    value: String,
}

impl Rule {
    fn validate(&self) -> Result<(), ApiError> {
        match self.rule_type {
            RuleType::IpCidr | RuleType::IpCidr6 | RuleType::SrcIpCidr
                if IpNet::from_str(&self.value).is_err() =>
            {
                return Err(ApiError::InvalidIpCidr(self.value.clone()));
            }
            RuleType::Domain | RuleType::DomainSuffix | RuleType::DomainKeyword
                if !is_valid_domain(&self.value) =>
            {
                return Err(ApiError::InvalidDomain(self.value.clone()));
            }
            RuleType::DstPort | RuleType::SrcPort | RuleType::InPort
                if !is_valid_port(&self.value) =>
            {
                return Err(ApiError::InvalidPort(self.value.clone()));
            }
            _ => {} // other types are not validated yet
        }
        Ok(())
    }
}

// An independently configurable rule set
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Ruleset {
    /// Display name
    name: String,
    /// Public URL identifier (immutable after creation)
    slug: String,
    /// Read access key; when None the public endpoint needs no key
    read_key: Option<String>,
    /// Creation time (unix seconds)
    created_at: u64,
    /// Rules in insertion order
    #[serde(default)]
    rules: Vec<Rule>,
}

// ---- Request/response structs ----

#[derive(Debug, Deserialize)]
struct CreateRuleset {
    name: String,
    #[serde(default)]
    slug: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateRuleset {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    require_key: Option<bool>,
}

#[derive(Debug, Serialize)]
struct RulesetSummary {
    name: String,
    slug: String,
    rule_count: usize,
    url: String,
    protected: bool,
}

#[derive(Debug, Serialize)]
struct RulesetDetail {
    name: String,
    slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    read_key: Option<String>,
    protected: bool,
    url: String,
    rules: Vec<Rule>,
}

// ---- Management API (token required) ----

async fn list_rulesets() -> Result<Json<Vec<RulesetSummary>>, ApiError> {
    let map = RULESETS.lock().await;
    let mut list: Vec<RulesetSummary> = map.values().map(summary_for).collect();
    list.sort_by(|a, b| a.slug.cmp(&b.slug));
    Ok(Json(list))
}

async fn get_ruleset(Path(slug): Path<String>) -> Result<Json<RulesetDetail>, ApiError> {
    let map = RULESETS.lock().await;
    let ruleset = map.get(&slug).ok_or(ApiError::RulesetNotFound)?;
    Ok(Json(detail_for(ruleset)))
}

async fn create_ruleset(
    Json(body): Json<CreateRuleset>,
) -> Result<(StatusCode, Json<RulesetSummary>), ApiError> {
    let name = body.name.trim().to_string();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(ApiError::InvalidName);
    }

    let mut map = RULESETS.lock().await;
    if map.values().any(|r| r.name == name) {
        return Err(ApiError::DuplicateName);
    }

    let base = match body.slug {
        Some(raw) if !raw.trim().is_empty() => {
            let slug = slugify(&raw);
            if !valid_slug(&slug) {
                return Err(ApiError::InvalidSlug);
            }
            slug
        }
        _ => slugify(&name),
    };
    let slug = unique_slug(&base, &map);

    let ruleset = Ruleset {
        name,
        slug: slug.clone(),
        read_key: Some(generate_secret()),
        created_at: now_unix(),
        rules: Vec::new(),
    };
    let summary = summary_for(&ruleset);
    map.insert(slug, ruleset);
    drop(map);

    save_rulesets().await?;
    Ok((StatusCode::CREATED, Json(summary)))
}

async fn update_ruleset(
    Path(slug): Path<String>,
    Json(body): Json<UpdateRuleset>,
) -> Result<Json<RulesetDetail>, ApiError> {
    let mut map = RULESETS.lock().await;
    if !map.contains_key(&slug) {
        return Err(ApiError::RulesetNotFound);
    }

    if let Some(name) = body.name {
        let name = name.trim().to_string();
        if name.is_empty() || name.chars().count() > 64 {
            return Err(ApiError::InvalidName);
        }
        if map.iter().any(|(s, r)| s != &slug && r.name == name) {
            return Err(ApiError::DuplicateName);
        }
        map.get_mut(&slug).unwrap().name = name;
    }

    if let Some(require_key) = body.require_key {
        let ruleset = map.get_mut(&slug).unwrap();
        if require_key && ruleset.read_key.is_none() {
            ruleset.read_key = Some(generate_secret());
        } else if !require_key {
            ruleset.read_key = None;
        }
    }

    let detail = detail_for(map.get(&slug).unwrap());
    drop(map);
    save_rulesets().await?;
    Ok(Json(detail))
}

async fn delete_ruleset(Path(slug): Path<String>) -> Result<StatusCode, ApiError> {
    let mut map = RULESETS.lock().await;
    if map.remove(&slug).is_none() {
        return Err(ApiError::RulesetNotFound);
    }
    drop(map);
    save_rulesets().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_rules(Path(slug): Path<String>) -> Result<Json<Vec<Rule>>, ApiError> {
    let map = RULESETS.lock().await;
    let ruleset = map.get(&slug).ok_or(ApiError::RulesetNotFound)?;
    Ok(Json(ruleset.rules.clone()))
}

async fn add_rule(
    Path(slug): Path<String>,
    Json(rule): Json<Rule>,
) -> Result<StatusCode, ApiError> {
    rule.validate()?;

    let mut map = RULESETS.lock().await;
    let ruleset = map.get_mut(&slug).ok_or(ApiError::RulesetNotFound)?;
    if ruleset.rules.contains(&rule) {
        return Err(ApiError::DuplicateRule);
    }
    ruleset.rules.push(rule);
    drop(map);

    save_rulesets().await?;
    Ok(StatusCode::CREATED)
}

async fn delete_rule(
    Path(slug): Path<String>,
    Json(rule): Json<Rule>,
) -> Result<StatusCode, ApiError> {
    let mut map = RULESETS.lock().await;
    let ruleset = map.get_mut(&slug).ok_or(ApiError::RulesetNotFound)?;
    let len = ruleset.rules.len();
    ruleset.rules.retain(|r| r != &rule);
    if ruleset.rules.len() == len {
        return Err(ApiError::RuleNotFound);
    }
    drop(map);
    save_rulesets().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- Public plain-text endpoint (no token, for clients to fetch) ----

async fn public_ruleset(
    Path(slug): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, ApiError> {
    let map = RULESETS.lock().await;
    let ruleset = map.get(&slug).ok_or(ApiError::RulesetNotFound)?;

    // A read-protected rule set must be fetched with the correct k parameter;
    // otherwise 404 hides its existence
    if let Some(key) = &ruleset.read_key {
        let provided = query.get("k").map(|v| v.as_str()).unwrap_or("");
        if !constant_time_eq(provided, key) {
            return Err(ApiError::RulesetNotFound);
        }
    }

    let mut text = String::new();
    for rule in &ruleset.rules {
        text.push_str(&format!("{},{}\n", rule.rule_type, rule.value));
    }
    Ok(text) // axum sets text/plain; charset=utf-8 for String
}

// ---- Auth middleware ----

async fn require_auth(req: Request, next: Next) -> Result<Response, ApiError> {
    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or("");
    if !constant_time_eq(provided, &ADMIN_TOKEN) {
        return Err(ApiError::Unauthorized);
    }
    Ok(next.run(req).await)
}

// ---- Static assets and SPA fallback ----

/// Unmatched requests: management API prefixes get a JSON 404; everything else is served
/// as a static file, falling back to index.html when the file is missing and the path
/// does not look like an asset (handy for the SPA and during development)
async fn spa_fallback(uri: Uri) -> Response {
    let path = uri.path();
    if path.starts_with("/api") || path.starts_with("/rulesets") {
        return ApiError::NotFound.into_response();
    }

    let rel = path.trim_start_matches('/');
    // Path traversal guard
    if rel.contains("..") || rel.contains('\\') {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    let is_asset = path.starts_with("/assets/");
    let target = if rel.is_empty() || rel.ends_with('/') {
        format!("{}/index.html", FE_DIR.as_str())
    } else {
        format!("{}/{}", FE_DIR.as_str(), rel)
    };

    match fs::read(&target).await {
        Ok(bytes) => {
            let mut response = Response::new(Body::from(bytes));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(mime_for(&target)),
            );
            // Hashed build assets are cacheable for a long time; the entry page is not
            let cache = if is_asset {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            };
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
            response
        }
        Err(_) => {
            if path[1..].contains('.') {
                // Missing asset-like resource: 404
                return (StatusCode::NOT_FOUND, "not found").into_response();
            }
            let mut response = Response::new(Body::from(INDEX_HTML.clone()));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            response
        }
    }
}

fn mime_for(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("");
    match ext {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

// ---- Helpers ----

fn summary_for(ruleset: &Ruleset) -> RulesetSummary {
    RulesetSummary {
        name: ruleset.name.clone(),
        slug: ruleset.slug.clone(),
        rule_count: ruleset.rules.len(),
        url: format!("/r/{}", ruleset.slug),
        protected: ruleset.read_key.is_some(),
    }
}

fn detail_for(ruleset: &Ruleset) -> RulesetDetail {
    RulesetDetail {
        name: ruleset.name.clone(),
        slug: ruleset.slug.clone(),
        read_key: ruleset.read_key.clone(),
        protected: ruleset.read_key.is_some(),
        url: format!("/r/{}", ruleset.slug),
        rules: ruleset.rules.clone(),
    }
}

/// Generate 32 random bytes as a hex string
fn generate_secret() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("system RNG unavailable");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Turn any name into a safe URL slug (lowercase alphanumerics + hyphens)
fn slugify(input: &str) -> String {
    let mut slug = String::with_capacity(input.len());
    for ch in input.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        "ruleset".to_string()
    } else {
        slug
    }
}

fn valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 64
        && !slug.starts_with('-')
        && !slug.ends_with('-')
        && slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Generate a slug that does not collide with existing ones
fn unique_slug(base: &str, map: &HashMap<String, Ruleset>) -> String {
    if !map.contains_key(base) {
        return base.to_string();
    }
    let mut n = 2;
    loop {
        let candidate = format!("{base}-{n}");
        if !map.contains_key(&candidate) {
            return candidate;
        }
        n += 1;
    }
}

/// Constant-time string comparison to avoid timing side channels
fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---- Validators ----

fn is_valid_domain(domain: &str) -> bool {
    let domain_regex = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9-_.]+[a-zA-Z0-9]$").unwrap();
    domain_regex.is_match(domain)
}

fn is_valid_port(port: &str) -> bool {
    match port.parse::<u16>() {
        Ok(_) => true,
        Err(_) => {
            // Port range format, e.g. 80-443
            let parts: Vec<&str> = port.split('-').collect();
            parts.len() == 2 && parts[0].parse::<u16>().is_ok() && parts[1].parse::<u16>().is_ok()
        }
    }
}

// ---- Persistence ----

/// Atomic write: temp file + rename, so a crash mid-write cannot corrupt the data file
async fn save_rulesets() -> Result<(), ApiError> {
    let map = RULESETS.lock().await;
    let mut list: Vec<&Ruleset> = map.values().collect();
    list.sort_by(|a, b| a.slug.cmp(&b.slug));
    let json = serde_json::to_string_pretty(&list)?;
    let file = DATA_FILE.clone();
    let tmp = format!("{file}.tmp");
    fs::write(&tmp, json).await?;
    fs::rename(&tmp, file).await?;
    Ok(())
}

/// Load the data file at startup; a missing file is ignored, a broken one warns and starts empty
async fn load_rulesets() -> Result<(), ApiError> {
    let content = match fs::read_to_string(DATA_FILE.clone()).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(ApiError::IoError(e)),
    };
    let list: Vec<Ruleset> = serde_json::from_str(&content)?;
    let mut map = RULESETS.lock().await;
    for ruleset in list {
        map.insert(ruleset.slug.clone(), ruleset);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Force admin token initialization (auto-generates and logs it when unset)
    let _ = &*ADMIN_TOKEN;

    if let Err(e) = load_rulesets().await {
        tracing::warn!("Failed to load rules data; starting empty: {e}");
    }

    let bind_addr = env::var(ENV_BIND_ADDR).unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());
    let addr: SocketAddr = bind_addr.parse().map_err(|_| {
        format!("Invalid bind address {bind_addr} (expected host:port, e.g. 127.0.0.1:3500)")
    })?;

    let app = Router::new()
        .route("/rulesets", get(list_rulesets).post(create_ruleset))
        .route(
            "/rulesets/{slug}",
            get(get_ruleset)
                .patch(update_ruleset)
                .delete(delete_ruleset),
        )
        .route(
            "/rulesets/{slug}/rules",
            get(get_rules).post(add_rule).delete(delete_rule),
        )
        .route_layer(middleware::from_fn(require_auth))
        .route("/r/{slug}", get(public_ruleset))
        .fallback(spa_fallback)
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(CompressionLayer::new());

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(
        "Server listening on {addr}; data file: {}; static dir: {}; admin token configured ({} bytes)",
        DATA_FILE.as_str(),
        FE_DIR.as_str(),
        ADMIN_TOKEN.len()
    );

    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ruleset(slug: &str) -> Ruleset {
        Ruleset {
            name: slug.to_string(),
            slug: slug.to_string(),
            read_key: None,
            created_at: 0,
            rules: Vec::new(),
        }
    }

    #[test]
    fn slugify_basic() {
        assert_eq!(slugify("Ads Block"), "ads-block");
        assert_eq!(slugify("Google Ads!!"), "google-ads");
        assert_eq!(slugify("  Mixed_Case--Name  "), "mixed-case-name");
        assert_eq!(slugify("---"), "ruleset");
        assert_eq!(slugify("ééé"), "ruleset");
    }

    #[test]
    fn unique_slug_appends_suffix() {
        let mut map = HashMap::new();
        map.insert("ads".to_string(), sample_ruleset("ads"));
        assert_eq!(unique_slug("ads", &map), "ads-2");
        map.insert("ads-2".to_string(), sample_ruleset("ads-2"));
        assert_eq!(unique_slug("ads", &map), "ads-3");
        assert_eq!(unique_slug("free", &map), "free");
    }

    #[test]
    fn valid_slug_rejects_bad_input() {
        assert!(valid_slug("ads-block"));
        assert!(valid_slug("a"));
        assert!(!valid_slug("-ads"));
        assert!(!valid_slug("ads-"));
        assert!(!valid_slug("Ads")); // lowercase only
        assert!(!valid_slug("ads_block"));
        assert!(!valid_slug(""));
    }

    #[test]
    fn constant_time_eq_compares() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(!constant_time_eq("", "a"));
    }

    #[test]
    fn port_validation() {
        assert!(is_valid_port("80"));
        assert!(is_valid_port("80-443"));
        assert!(!is_valid_port("70000"));
        assert!(!is_valid_port("80-"));
        assert!(!is_valid_port("80-443-1"));
        assert!(!is_valid_port("a"));
    }

    #[test]
    fn domain_validation() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("a.b-c.example.com"));
        assert!(!is_valid_domain("-bad.example.com"));
        assert!(!is_valid_domain("a"));
        assert!(!is_valid_domain("ab"));
        assert!(!is_valid_domain(""));
    }
}
