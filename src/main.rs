use axum::{
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use ipnet::IpNet;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::str::FromStr;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::{fs, net::TcpListener};

const RULES_FILE: &str = "rules.json";

// 使用全局变量存储规则
static RULES: Lazy<Mutex<Vec<Rule>>> = Lazy::new(|| tokio::sync::Mutex::new(Vec::new()));

// 自定义错误类型
#[derive(Error, Debug)]
pub enum RuleError {
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
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

// 实现自定义响应
impl IntoResponse for RuleError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            RuleError::InvalidIpCidr(_) => StatusCode::BAD_REQUEST,
            RuleError::InvalidDomain(_) => StatusCode::BAD_REQUEST,
            RuleError::InvalidPort(_) => StatusCode::BAD_REQUEST,
            RuleError::DuplicateRule => StatusCode::CONFLICT,
            RuleError::RuleNotFound => StatusCode::NOT_FOUND,
            RuleError::IoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            RuleError::JsonError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = Json(serde_json::json!({
            "error": self.to_string()
        }));
        (status, body).into_response()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
struct Rule {
    rule_type: RuleType,
    value: String,
}

// 为Rule实现验证
impl Rule {
    fn validate(&self) -> Result<(), RuleError> {
        match self.rule_type {
            RuleType::IpCidr | RuleType::IpCidr6 | RuleType::SrcIpCidr => {
                if IpNet::from_str(&self.value).is_err() {
                    return Err(RuleError::InvalidIpCidr(self.value.clone()));
                }
            }
            RuleType::Domain | RuleType::DomainSuffix | RuleType::DomainKeyword => {
                if !is_valid_domain(&self.value) {
                    return Err(RuleError::InvalidDomain(self.value.clone()));
                }
            }
            RuleType::DstPort | RuleType::SrcPort | RuleType::InPort => {
                if !is_valid_port(&self.value) {
                    return Err(RuleError::InvalidPort(self.value.clone()));
                }
            }
            _ => {} // 其他类型暂时不做验证
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
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

// 处理获取规则列表的请求
async fn get_rules() -> impl IntoResponse {
    let rules = RULES.lock().await;
    let mut text = String::new();
    for rule in rules.iter() {
        text.push_str(&format!("{},{}\n", rule.rule_type.to_string(), rule.value));
    }
    text
}

// 处理添加新规则的请求
async fn add_rule(Json(rule): Json<Rule>) -> Result<impl IntoResponse, RuleError> {
    // 验证规则
    rule.validate()?;

    // 检查重复
    let mut rules = RULES.lock().await;
    if rules.contains(&rule) {
        return Err(RuleError::DuplicateRule);
    }

    // 添加规则
    rules.push(rule);
    drop(rules); // 释放锁

    // 持久化存储
    save_rules().await?;

    Ok(StatusCode::CREATED)
}

// 处理删除规则的请求
async fn delete_rule(Json(rule): Json<Rule>) -> Result<impl IntoResponse, RuleError> {
    let mut rules = RULES.lock().await;
    let len = rules.len();
    rules.retain(|r| r != &rule);

    if rules.len() == len {
        return Err(RuleError::RuleNotFound);
    }

    drop(rules); // 释放锁

    // 持久化存储
    save_rules().await?;

    Ok(StatusCode::NO_CONTENT)
}

impl std::fmt::Display for RuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use RuleType::*;
        match self {
            Domain => write!(f, "DOMAIN"),
            DomainSuffix => write!(f, "DOMAIN-SUFFIX"),
            DomainKeyword => write!(f, "DOMAIN-KEYWORD"),
            DomainWildcard => write!(f, "DOMAIN-WILDCARD"),
            DomainRegex => write!(f, "DOMAIN-REGEX"),
            Geosite => write!(f, "GEOSITE"),
            IpCidr => write!(f, "IP-CIDR"),
            IpCidr6 => write!(f, "IP-CIDR6"),
            IpSuffix => write!(f, "IP-SUFFIX"),
            IpAsn => write!(f, "IP-ASN"),
            Geoip => write!(f, "GEOIP"),
            SrcGeoip => write!(f, "SRC-GEOIP"),
            SrcIpAsn => write!(f, "SRC-IP-ASN"),
            SrcIpCidr => write!(f, "SRC-IP-CIDR"),
            SrcIpSuffix => write!(f, "SRC-IP-SUFFIX"),
            DstPort => write!(f, "DST-PORT"),
            SrcPort => write!(f, "SRC-PORT"),
            InPort => write!(f, "IN-PORT"),
            InType => write!(f, "IN-TYPE"),
            InUser => write!(f, "IN-USER"),
            InName => write!(f, "IN-NAME"),
            ProcessPath => write!(f, "PROCESS-PATH"),
            ProcessPathRegex => write!(f, "PROCESS-PATH-REGEX"),
            ProcessName => write!(f, "PROCESS-NAME"),
            ProcessNameRegex => write!(f, "PROCESS-NAME-REGEX"),
            Uid => write!(f, "UID"),
            Network => write!(f, "NETWORK"),
            Dscp => write!(f, "DSCP"),
            Match => write!(f, "MATCH"),
        }
    }
}

// 验证域名格式
fn is_valid_domain(domain: &str) -> bool {
    let domain_regex = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9-_.]+[a-zA-Z0-9]$").unwrap();
    domain_regex.is_match(domain)
}

// 验证端口格式
fn is_valid_port(port: &str) -> bool {
    match port.parse::<u16>() {
        Ok(_) => true,
        Err(_) => {
            // 检查是否是端口范围格式 (例如: 80-443)
            let parts: Vec<&str> = port.split('-').collect();
            if parts.len() == 2 {
                parts[0].parse::<u16>().is_ok() && parts[1].parse::<u16>().is_ok()
            } else {
                false
            }
        }
    }
}

// 持久化规则到文件
async fn save_rules() -> Result<(), RuleError> {
    let rules = RULES.lock().await;
    let rules_vec = &*rules; // 获取对 Vec<Rule> 的引用
    let json = serde_json::to_string_pretty(&rules_vec)?;
    fs::write(RULES_FILE, json).await?;
    Ok(())
}

// 从文件加载规则
async fn load_rules() -> Result<(), RuleError> {
    if let Ok(content) = fs::read_to_string(RULES_FILE).await {
        let loaded_rules: Vec<Rule> = serde_json::from_str(&content)?;
        let mut rules = RULES.lock().await;
        *rules = loaded_rules;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志
    tracing_subscriber::fmt::init();

    // 加载已存在的规则
    if let Err(e) = load_rules().await {
        tracing::warn!("Failed to load rules: {}", e);
    }

    // gzip compression layer
    let compression_layer = tower_http::compression::CompressionLayer::new();

    let app = Router::new()
        .route("/rules", get(get_rules))
        .route("/rules", post(add_rule))
        .route("/rules", delete(delete_rule))
        .layer(compression_layer);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3500));
    let listener = TcpListener::bind(addr).await?;

    tracing::info!("Server running on http://{}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}
